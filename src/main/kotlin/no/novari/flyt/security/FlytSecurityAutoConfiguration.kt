package no.novari.flyt.security

import jakarta.servlet.DispatcherType
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.ManagementWebSecurityAutoConfiguration
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.OAuth2ResourceServerWebSecurityAutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.core.convert.converter.Converter
import org.springframework.http.HttpStatus
import org.springframework.security.access.hierarchicalroles.RoleHierarchy
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.HttpStatusAccessDeniedHandler
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher
import org.springframework.security.web.util.matcher.OrRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * One filter chain per caller type, in a fixed order, and deny-all for everything else.
 *
 * Each chain decodes with the app's `JwtDecoder` (Spring's checks of signature, time and issuer) and adds its own
 * checks from [FlytTokenValidators]. A token that fails them gives 401.
 */
@AutoConfiguration(
    before = [
        OAuth2ResourceServerWebSecurityAutoConfiguration::class,
        ManagementWebSecurityAutoConfiguration::class,
        ServletWebSecurityAutoConfiguration::class,
    ],
)
@EnableMethodSecurity
@EnableConfigurationProperties(FlytSecurityProperties::class)
public class FlytSecurityAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public fun userRoleResolver(properties: FlytSecurityProperties): UserRoleResolver =
        PolicyUserRoleResolver(properties)

    @Bean
    public fun roleHierarchy(): RoleHierarchy =
        RoleHierarchyImpl
            .withDefaultRolePrefix()
            .role(UserRole.DEVELOPER.name)
            .implies(UserRole.ADMIN.name)
            .role(UserRole.ADMIN.name)
            .implies(UserRole.USER.name)
            .build()

    @Bean
    @Order(1)
    public fun flytPublicFilterChain(
        http: HttpSecurity,
        properties: FlytSecurityProperties,
    ): SecurityFilterChain {
        val matchers = listOf(EndpointRequest.to("health", "prometheus")) + properties.publicPaths.map(::path)
        return http
            .common()
            .securityMatcher(OrRequestMatcher(matchers))
            .authorizeHttpRequests { it.anyRequest().permitAll() }
            .build()
    }

    @Bean
    @Order(2)
    public fun flytInternalClientFilterChain(
        http: HttpSecurity,
        jwtDecoder: JwtDecoder,
        properties: FlytSecurityProperties,
    ): SecurityFilterChain {
        val authorizedClients = properties.internalClient.authorizedClientIds.map { clientAuthority(it).authority }
        return http
            .common()
            .securityMatcher(path("${UrlPaths.INTERNAL_CLIENT_API}/**"))
            .jwt(
                jwtDecoder.validatedBy(FlytTokenValidators.internalClient()),
            ) { listOf(clientAuthority(checkNotNull(it.subject))) }
            .authorizeHttpRequests {
                if (authorizedClients.isEmpty()) {
                    it.anyRequest().denyAll()
                } else {
                    it.anyRequest().hasAnyAuthority(*authorizedClients.toTypedArray())
                }
            }.build()
    }

    @Bean
    @Order(3)
    @ConditionalOnProperty("novari.flyt.security.user.audience")
    public fun flytUserFilterChain(
        http: HttpSecurity,
        jwtDecoder: JwtDecoder,
        properties: FlytSecurityProperties,
        userRoleResolver: UserRoleResolver,
    ): SecurityFilterChain {
        val validator =
            FlytTokenValidators.user(
                audience = requireNotNull(properties.user.audience),
                allowedOrgIds = properties.tenantOrgIds + properties.roles.operatorOrgIds,
            )
        return http
            .common()
            .securityMatcher(path("${UrlPaths.INTERNAL_API}/**"))
            .jwt(jwtDecoder.validatedBy(validator), userRoleResolver::resolve)
            .authorizeHttpRequests { it.anyRequest().hasRole(UserRole.USER.name) }
            .build()
    }

    @Bean
    @Order(4)
    @ConditionalOnProperty("novari.flyt.security.external.expected-client-id")
    public fun flytSourceApplicationFilterChain(
        http: HttpSecurity,
        jwtDecoder: JwtDecoder,
        properties: FlytSecurityProperties,
    ): SecurityFilterChain {
        val external = properties.external
        val authority = SourceApplicationAuthority.of(requireNotNull(external.sourceApplicationId))
        val validator = FlytTokenValidators.sourceApplication(requireNotNull(external.expectedClientId))
        return http
            .common()
            .securityMatcher(OrRequestMatcher(external.paths.map(::path)))
            .jwt(jwtDecoder.validatedBy(validator)) { listOf(SimpleGrantedAuthority(authority)) }
            .authorizeHttpRequests { it.anyRequest().hasAuthority(authority) }
            .build()
    }

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    public fun flytDenyAllFilterChain(http: HttpSecurity): SecurityFilterChain =
        http
            .common()
            .exceptionHandling {
                it.authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                it.accessDeniedHandler(HttpStatusAccessDeniedHandler(HttpStatus.UNAUTHORIZED))
            }.authorizeHttpRequests {
                // The error page for a request a chain above already let through, such as 503 from FlytAccess.
                it.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                it.anyRequest().denyAll()
            }.build()

    // Bearer tokens only: no session, so no session cookie can authenticate a request, and CSRF does not apply.
    private fun HttpSecurity.common(): HttpSecurity =
        csrf { it.disable() }
            .httpBasic { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }

    private fun HttpSecurity.jwt(
        decoder: JwtDecoder,
        authorities: (Jwt) -> Collection<GrantedAuthority>,
    ): HttpSecurity =
        oauth2ResourceServer { resourceServer ->
            resourceServer.jwt { jwt ->
                jwt.decoder(decoder)
                jwt.jwtAuthenticationConverter(
                    JwtAuthenticationConverter().apply {
                        setJwtGrantedAuthoritiesConverter(
                            Converter { authorities(it) },
                        )
                    },
                )
            }
        }

    private fun clientAuthority(clientId: String) = SimpleGrantedAuthority("CLIENT_ID_$clientId")

    private fun path(pattern: String): RequestMatcher = PathPatternRequestMatcher.withDefaults().matcher(pattern)
}
