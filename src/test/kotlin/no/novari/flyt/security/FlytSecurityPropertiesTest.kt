package no.novari.flyt.security

import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class FlytSecurityPropertiesTest {
    @ParameterizedTest
    @ValueSource(strings = ["/api/**", "/api/acos/swagger-ui/**", "/**", "/*/swagger-ui", "/{segment}/x"])
    fun `public paths reject patterns that can match routes under api`(path: String) {
        assertThatThrownBy { FlytSecurityProperties(publicPaths = listOf(path)) }
            .isInstanceOf(IllegalArgumentException::class.java)
    }

    @ParameterizedTest
    @ValueSource(strings = ["/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**", "/api/eapply/v3/api-docs"])
    fun `public paths accept Swagger routes`(path: String) {
        assertThatCode { FlytSecurityProperties(publicPaths = listOf(path)) }.doesNotThrowAnyException()
    }

    @ParameterizedTest
    @ValueSource(strings = ["/api/**", "/**", "/api/*/instances", "/api/intern/**", "/api/intern-klient/**"])
    fun `external paths must be explicit gateway routes`(path: String) {
        assertThatThrownBy { external(path) }.isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `external needs source application and paths together`() {
        assertThatCode { external("/api/acos/**") }.doesNotThrowAnyException()
        assertThatThrownBy {
            FlytSecurityProperties(external = FlytSecurityProperties.External(listOf("/api/acos/**")))
        }.isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy {
            FlytSecurityProperties(
                external = FlytSecurityProperties.External(sourceApplication = SourceApplication.ACOS),
            )
        }.isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `user audience needs tenant org ids`() {
        assertThatThrownBy {
            FlytSecurityProperties(user = FlytSecurityProperties.User(audience = "frontend"))
        }.isInstanceOf(IllegalArgumentException::class.java)
    }

    private fun external(path: String) =
        FlytSecurityProperties(
            external = FlytSecurityProperties.External(listOf(path), SourceApplication.ACOS),
        )
}
