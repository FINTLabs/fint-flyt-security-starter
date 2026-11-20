package no.novari.flyt.security

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.test.web.client.ExpectedCount.once
import org.springframework.test.web.client.MockRestServiceServer
import org.springframework.test.web.client.match.MockRestRequestMatchers.method
import org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo
import org.springframework.test.web.client.response.MockRestResponseCreators.withStatus
import org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess
import org.springframework.web.client.RestClient
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
import org.springframework.web.server.ResponseStatusException

class FlytAccessTest {
    private val builder = RestClient.builder().baseUrl("http://authz")
    private val server = MockRestServiceServer.bindTo(builder).build()
    private val flytAccess = FlytAccess(builder.build())

    @BeforeEach
    fun setUp() {
        RequestContextHolder.setRequestAttributes(ServletRequestAttributes(MockHttpServletRequest()))
        val jwt =
            Jwt
                .withTokenValue("token")
                .header("alg", "none")
                .claim("objectidentifier", OID)
                .build()
        SecurityContextHolder.getContext().authentication = JwtAuthenticationToken(jwt)
    }

    @AfterEach
    fun tearDown() {
        RequestContextHolder.resetRequestAttributes()
        SecurityContextHolder.clearContext()
    }

    @Test
    fun `fetches the user's source applications once per request`() {
        expectCall().andRespond(withSuccess("[1,3]", MediaType.APPLICATION_JSON))

        assertThat(flytAccess.hasSourceApplication(1)).isTrue()
        assertThat(flytAccess.hasSourceApplication(2)).isFalse()
        assertThat(flytAccess.sourceApplicationIds()).containsExactlyInAnyOrder(1, 3)
        server.verify()
    }

    @Test
    fun `unknown user has no source applications`() {
        expectCall().andRespond(withSuccess("[]", MediaType.APPLICATION_JSON))

        assertThat(flytAccess.hasSourceApplication(1)).isFalse()
    }

    @Test
    fun `404 gives 503, so a missing route does not look like no access`() {
        expectCall().andRespond(withStatus(HttpStatus.NOT_FOUND))

        assertServiceUnavailable()
    }

    @Test
    fun `error gives 503`() {
        expectCall().andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR))

        assertServiceUnavailable()
    }

    private fun expectCall() =
        server
            .expect(once(), requestTo("http://authz/users/$OID/source-application-ids"))
            .andExpect(method(HttpMethod.GET))

    private fun assertServiceUnavailable() {
        assertThatThrownBy { flytAccess.hasSourceApplication(1) }
            .isInstanceOfSatisfying(ResponseStatusException::class.java) {
                assertThat(it.statusCode).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE)
            }
    }

    private companion object {
        const val OID = "7d9e0d20-2a50-4ca1-9e4f-7c79f5fbe6c0"
    }
}
