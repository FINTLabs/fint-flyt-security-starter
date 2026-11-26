package no.novari.flyt.security

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController

@SpringBootApplication
class TestApplication

@RestController
class TestController {
    // Spring Security 7 adds FACTOR_BEARER for bearer tokens. Only our authorities matter here.
    @GetMapping(
        "/api/intern/test",
        "/api/intern-klient/test",
        "/api/acos/test",
        "/api/other/test",
        "/swagger-ui.html",
    )
    fun authorities(authentication: Authentication?): Set<String> =
        authentication
            ?.authorities
            ?.mapNotNull { it.authority }
            ?.filterNot { it.startsWith("FACTOR_") }
            ?.toSortedSet()
            .orEmpty()

    @GetMapping("/api/intern/admin")
    @PreAuthorize("hasRole('ADMIN')")
    fun admin(): String = "admin"

    @GetMapping("/api/intern/source-applications/{sourceApplicationId}")
    @PreAuthorize("@flyt.hasSourceApplication(#sourceApplicationId)")
    fun sourceApplication(
        @PathVariable sourceApplicationId: Long,
    ): String = "ok"

    @GetMapping("/api/acos/source-application-id")
    fun sourceApplicationId(authentication: Authentication): Long = authentication.sourceApplicationId()
}
