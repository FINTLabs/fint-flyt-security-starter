package no.novari.flyt.security.support

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.sun.net.httpserver.HttpServer
import no.novari.flyt.security.UserRole
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.test.context.DynamicPropertyRegistry
import java.net.InetAddress
import java.net.InetSocketAddress
import java.time.Instant
import java.util.UUID

/**
 * Signed NAM-like tokens for HTTP tests. The test JWK is made once per JVM, and the app's own `JwtDecoder` verifies
 * the tokens against it through `spring.security.oauth2.resourceserver.jwt.jwk-set-uri`.
 */
object TestTokens {
    const val ISSUER = "https://idp.test/nidp/oauth/nam"
    const val USER_AUDIENCE = "fint-flyt-auth-forward-sso"
    const val INTERNAL_CLIENT_ID = "fint-flyt-authorization-oauth2-client"
    const val SOURCE_APPLICATION_CLIENT_ID = "fint-flyt-acos-oauth2-client"
    const val TENANT_ORG_ID = "fintlabs.no"
    const val ADDITIONAL_ORG_ID = "viken.no"
    const val OPERATOR_ORG_ID = "vigo.no"

    private val jwk: RSAKey = RSAKeyGenerator(2048).keyID("test").keyUse(KeyUse.SIGNATURE).generate()
    private val encoder = NimbusJwtEncoder(ImmutableJWKSet(JWKSet(jwk)))

    /** Serves the public test JWK like NAM's JWKS endpoint. The issuer is only used to validate `iss`. */
    private val jwkSetUri: String by lazy {
        val body = JWKSet(jwk.toPublicJWK()).toString().toByteArray()
        val server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
        server.createContext("/jwks") { exchange ->
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        server.start()
        "http://localhost:${server.address.port}/jwks"
    }

    fun register(registry: DynamicPropertyRegistry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri") { jwkSetUri }
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri") { ISSUER }
    }

    fun user(
        organizationId: String = TENANT_ORG_ID,
        roles: Set<UserRole> = setOf(UserRole.USER),
        objectIdentifier: String = UUID.randomUUID().toString(),
        audience: String = USER_AUDIENCE,
        customize: (JwtClaimsSet.Builder) -> Unit = {},
    ): String =
        sign {
            it
                .subject("opaque-user-id")
                .audience(listOf(audience))
                .claim("scope", "end-user-profile fint-api")
                .claim("organizationid", organizationId)
                .claim("objectidentifier", objectIdentifier)
                .claim("roles", roles.map(UserRole::claimValue))
            customize(it)
        }

    /** An ID token from the same login: same aud, but no scope, and with nonce. */
    fun idToken(): String =
        user {
            it.claims { claims -> claims.remove("scope") }
            it.claim("nonce", "n-0S6_WzA2Mj")
        }

    /** NAM sets aud to the client that asked for the token, so aud is sub for client_credentials. */
    fun client(
        clientId: String,
        customize: (JwtClaimsSet.Builder) -> Unit = {},
    ): String =
        sign {
            it.subject(clientId).audience(listOf(clientId)).claim("scope", "end-user-profile fint-api")
            customize(it)
        }

    fun withoutExpiry(builder: JwtClaimsSet.Builder) {
        builder.claims { it.remove("exp") }
    }

    private fun sign(customize: (JwtClaimsSet.Builder) -> Unit): String {
        val now = Instant.now()
        val claims =
            JwtClaimsSet
                .builder()
                .issuer(ISSUER)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .also(customize)
                .build()
        val header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(jwk.keyID).build()
        return encoder.encode(JwtEncoderParameters.from(header, claims)).tokenValue
    }
}
