package no.novari.flyt.security

import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder
import org.springframework.boot.http.client.HttpClientSettings
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.http.converter.FormHttpMessageConverter
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.web.client.RestClient
import java.time.Duration

/** [FlytAccess] against authorization-service, when the app has the `authorization-service` client registration. */
@AutoConfiguration(after = [OAuth2ClientAutoConfiguration::class, FlytSecurityAutoConfiguration::class])
@ConditionalOnProperty(
    prefix = "spring.security.oauth2.client.registration.authorization-service",
    name = ["client-id"],
)
public class FlytAccessAutoConfiguration {
    @Bean("flyt")
    public fun flytAccess(
        clientRegistrationRepository: ClientRegistrationRepository,
        authorizedClientService: OAuth2AuthorizedClientService,
        restClientBuilder: RestClient.Builder,
        requestFactoryBuilder: ClientHttpRequestFactoryBuilder<*>,
        requestFactorySettings: HttpClientSettings,
        properties: FlytSecurityProperties,
    ): FlytAccess {
        val requestFactory = requestFactoryBuilder.build(requestFactorySettings.withDefaultTimeouts())

        // Same converters and error handler as the token client's default RestClient, plus our timeouts.
        val tokenResponseClient = RestClientClientCredentialsTokenResponseClient()
        tokenResponseClient.setRestClient(
            RestClient
                .builder()
                .requestFactory(requestFactory)
                .configureMessageConverters { converters ->
                    converters.addCustomConverter(FormHttpMessageConverter())
                    converters.addCustomConverter(OAuth2AccessTokenResponseHttpMessageConverter())
                }.defaultStatusHandler(OAuth2ErrorResponseErrorHandler())
                .build(),
        )
        val authorizedClientManager =
            AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientService)
        authorizedClientManager.setAuthorizedClientProvider(
            OAuth2AuthorizedClientProviderBuilder
                .builder()
                .clientCredentials { it.accessTokenResponseClient(tokenResponseClient) }
                .build(),
        )

        val interceptor = OAuth2ClientHttpRequestInterceptor(authorizedClientManager)
        interceptor.setClientRegistrationIdResolver { properties.authorization.clientRegistrationId }
        // The default resolves the incoming caller, which would fetch one token per user.
        interceptor.setPrincipalResolver { APP_PRINCIPAL }

        return FlytAccess(
            restClientBuilder
                .requestFactory(requestFactory)
                .requestInterceptor(interceptor)
                .baseUrl("${properties.authorization.baseUrl}/api/intern-klient/authorization")
                .build(),
        )
    }

    // The calls block incoming requests, so they must not fall back to the HTTP client's minutes-long defaults.
    // spring.http.clients.connect-timeout and read-timeout in the host app override these.
    private fun HttpClientSettings.withDefaultTimeouts(): HttpClientSettings =
        withTimeouts(connectTimeout() ?: DEFAULT_CONNECT_TIMEOUT, readTimeout() ?: DEFAULT_READ_TIMEOUT)

    private companion object {
        val APP_PRINCIPAL =
            AnonymousAuthenticationToken(
                "anonymous",
                "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"),
            )
        val DEFAULT_CONNECT_TIMEOUT: Duration = Duration.ofSeconds(2)
        val DEFAULT_READ_TIMEOUT: Duration = Duration.ofSeconds(5)
    }
}
