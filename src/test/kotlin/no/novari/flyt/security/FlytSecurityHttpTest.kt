package no.novari.flyt.security

import no.novari.flyt.security.support.TestTokens
import no.novari.flyt.security.support.TestTokens.ADDITIONAL_ORG_ID
import no.novari.flyt.security.support.TestTokens.INTERNAL_CLIENT_ID
import no.novari.flyt.security.support.TestTokens.OPERATOR_ORG_ID
import no.novari.flyt.security.support.TestTokens.SOURCE_APPLICATION_CLIENT_ID
import no.novari.flyt.security.support.TestTokens.TENANT_ORG_ID
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.mockito.Mockito.`when`
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.resttestclient.TestRestTemplate
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.web.server.ResponseStatusException

/** Signed tokens through the app's real `JwtDecoder` and the library's filter chains. */
@AutoConfigureTestRestTemplate
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class FlytSecurityHttpTest {
    @Autowired
    private lateinit var restTemplate: TestRestTemplate

    @MockitoBean(name = "flyt")
    private lateinit var flytAccess: FlytAccess

    @ParameterizedTest(name = "{0} with {1} gets {2}")
    @CsvSource(
        "$TENANT_ORG_ID, USER, 200, ROLE_USER",
        "$TENANT_ORG_ID, DEVELOPER, 200, ROLE_USER",
        "$ADDITIONAL_ORG_ID, USER, 200, ROLE_USER",
        "$OPERATOR_ORG_ID, USER, 200, ROLE_USER",
        "$OPERATOR_ORG_ID, DEVELOPER, 200, ROLE_DEVELOPER",
        "unknown.no, USER, 401, ",
    )
    fun `user roles are capped per organization`(
        organizationId: String,
        role: UserRole,
        status: Int,
        authority: String?,
    ) {
        val response = get("/api/intern/test", TestTokens.user(organizationId, setOf(role)))

        assertThat(response.statusCode.value()).isEqualTo(status)
        if (authority != null) assertThat(response.body).isEqualTo("[\"$authority\"]")
    }

    @Test
    fun `user token for another client gives 401`() {
        assertStatus("/api/intern/test", TestTokens.user(audience = "another-client"), HttpStatus.UNAUTHORIZED)
    }

    @Test
    fun `ID token gives 401`() {
        assertStatus("/api/intern/test", TestTokens.idToken(), HttpStatus.UNAUTHORIZED)
    }

    @Test
    fun `user token without exp gives 401`() {
        assertStatus(
            "/api/intern/test",
            TestTokens.user(customize = TestTokens::withoutExpiry),
            HttpStatus.UNAUTHORIZED,
        )
    }

    @Test
    fun `user token with an objectidentifier that is not a UUID gives 401`() {
        assertStatus("/api/intern/test", TestTokens.user(objectIdentifier = "1-1-1-1-1"), HttpStatus.UNAUTHORIZED)
    }

    @Test
    fun `user without a FLYT role gives 403`() {
        assertStatus("/api/intern/test", TestTokens.user(roles = emptySet()), HttpStatus.FORBIDDEN)
    }

    @Test
    fun `anonymous call to a protected route gives 401 while Swagger is public`() {
        assertStatus("/swagger-ui.html", null, HttpStatus.OK)
        assertStatus("/api/intern/test", null, HttpStatus.UNAUTHORIZED)
    }

    @Test
    fun `hasRole ADMIN gives 403 for USER and passes for ADMIN and DEVELOPER`() {
        val operator = { role: UserRole -> TestTokens.user(OPERATOR_ORG_ID, setOf(role)) }
        assertStatus("/api/intern/admin", operator(UserRole.USER), HttpStatus.FORBIDDEN)
        assertStatus("/api/intern/admin", operator(UserRole.ADMIN), HttpStatus.OK)
        assertStatus("/api/intern/admin", operator(UserRole.DEVELOPER), HttpStatus.OK)
    }

    @Test
    fun `tenant users are capped to USER and cannot use admin routes`() {
        assertStatus("/api/intern/admin", TestTokens.user(roles = setOf(UserRole.DEVELOPER)), HttpStatus.FORBIDDEN)
    }

    @Test
    fun `flyt hasSourceApplication protects a route`() {
        `when`(flytAccess.hasSourceApplication(1)).thenReturn(true)

        assertStatus("/api/intern/source-applications/1", TestTokens.user(), HttpStatus.OK)
        assertStatus("/api/intern/source-applications/2", TestTokens.user(), HttpStatus.FORBIDDEN)
    }

    @Test
    fun `authorization-service outage gives 503, not 401`() {
        `when`(flytAccess.hasSourceApplication(3))
            .thenThrow(ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Unable to verify user access"))

        assertStatus("/api/intern/source-applications/3", TestTokens.user(), HttpStatus.SERVICE_UNAVAILABLE)
    }

    @Test
    fun `the error page is not reachable directly`() {
        assertStatus("/error", null, HttpStatus.UNAUTHORIZED)
    }

    @Test
    fun `no session is created, so a cookie cannot replace the token`() {
        val response = get("/api/intern/test", TestTokens.user())

        assertThat(response.statusCode).isEqualTo(HttpStatus.OK)
        assertThat(response.headers[HttpHeaders.SET_COOKIE]).isNull()
    }

    @Test
    fun `token from another issuer gives 401`() {
        assertStatus(
            "/api/intern/test",
            TestTokens.user { it.issuer("https://other.idp/nidp/oauth/nam") },
            HttpStatus.UNAUTHORIZED,
        )
        assertStatus(
            "/api/intern-klient/test",
            TestTokens.client(INTERNAL_CLIENT_ID) { it.issuer("https://other.idp/nidp/oauth/nam") },
            HttpStatus.UNAUTHORIZED,
        )
    }

    @ParameterizedTest(name = "user token {0} gives 401")
    @CsvSource("without scope", "with nonce", "with at_hash")
    fun `each ID token claim alone gives 401`(case: String) {
        val token =
            TestTokens.user {
                when (case) {
                    "without scope" -> it.claims { claims -> claims.remove("scope") }
                    "with nonce" -> it.claim("nonce", "n-0S6_WzA2Mj")
                    else -> it.claim("at_hash", "77QmUPtjPfzWtF2AnpK9RQ")
                }
            }
        assertStatus("/api/intern/test", token, HttpStatus.UNAUTHORIZED)
    }

    @Test
    fun `internal client chain accepts only the authorized client`() {
        assertStatus("/api/intern-klient/test", TestTokens.client(INTERNAL_CLIENT_ID), HttpStatus.OK)
        assertStatus("/api/intern-klient/test", TestTokens.client("another-client"), HttpStatus.FORBIDDEN)
        assertStatus("/api/intern-klient/test", TestTokens.user(), HttpStatus.UNAUTHORIZED)
        assertStatus(
            "/api/intern-klient/test",
            TestTokens.client(INTERNAL_CLIENT_ID, TestTokens::withoutExpiry),
            HttpStatus.UNAUTHORIZED,
        )
    }

    @Test
    fun `client token whose aud is not its sub gives 401`() {
        val otherAudience: (JwtClaimsSet.Builder) -> Unit = { it.audience(listOf("another-client")) }
        assertStatus(
            "/api/intern-klient/test",
            TestTokens.client(INTERNAL_CLIENT_ID, otherAudience),
            HttpStatus.UNAUTHORIZED,
        )
        assertStatus(
            "/api/acos/test",
            TestTokens.client(SOURCE_APPLICATION_CLIENT_ID, otherAudience),
            HttpStatus.UNAUTHORIZED,
        )
    }

    @Test
    fun `source application chain accepts only the expected client`() {
        val token = TestTokens.client(SOURCE_APPLICATION_CLIENT_ID)
        assertStatus("/api/acos/test", token, HttpStatus.OK)
        assertThat(get("/api/acos/source-application-id", token).body).isEqualTo("1")
        assertStatus("/api/acos/test", TestTokens.client(INTERNAL_CLIENT_ID), HttpStatus.UNAUTHORIZED)
        assertStatus("/api/acos/test", TestTokens.client("another-client"), HttpStatus.UNAUTHORIZED)
        assertStatus("/api/acos/test", TestTokens.user(), HttpStatus.UNAUTHORIZED)
    }

    @Test
    fun `routes without a chain are denied`() {
        assertStatus("/api/other/test", TestTokens.client(SOURCE_APPLICATION_CLIENT_ID), HttpStatus.UNAUTHORIZED)
        assertStatus("/actuator/info", null, HttpStatus.UNAUTHORIZED)
    }

    @Test
    fun `health and prometheus are public`() {
        assertStatus("/actuator/health", null, HttpStatus.OK)
        assertStatus("/actuator/health/liveness", null, HttpStatus.OK)
        assertStatus("/actuator/prometheus", null, HttpStatus.OK)
    }

    private fun assertStatus(
        path: String,
        token: String?,
        status: HttpStatus,
    ) {
        assertThat(get(path, token).statusCode).describedAs(path).isEqualTo(status)
    }

    private fun get(
        path: String,
        token: String?,
    ): ResponseEntity<String> {
        val headers = HttpHeaders()
        token?.let(headers::setBearerAuth)
        return restTemplate.exchange(path, HttpMethod.GET, HttpEntity<Void>(headers), String::class.java)
    }

    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun properties(registry: DynamicPropertyRegistry) = TestTokens.register(registry)
    }
}
