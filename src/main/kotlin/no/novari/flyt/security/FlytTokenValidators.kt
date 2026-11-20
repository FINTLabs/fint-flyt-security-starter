package no.novari.flyt.security

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtAudienceValidator
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtTimestampValidator
import org.springframework.security.oauth2.jwt.JwtValidationException
import java.util.UUID

/** Checks per caller type, on top of the app's `JwtDecoder` with Spring's defaults (signature, time, issuer). */
internal object FlytTokenValidators {
    fun user(
        audience: String,
        allowedOrgIds: Set<String>,
    ): OAuth2TokenValidator<Jwt> =
        DelegatingOAuth2TokenValidator(
            expiryRequired(),
            // An ID token from the same login has the same aud. Only access tokens have scope.
            claim("must be an access token") {
                it.hasClaim("scope") && !it.hasClaim(IdTokenClaimNames.NONCE) && !it.hasClaim(IdTokenClaimNames.AT_HASH)
            },
            JwtAudienceValidator(audience),
            claim("organizationid is not allowed") { it.getClaimAsString(UserClaims.ORGANIZATION_ID) in allowedOrgIds },
            claim("objectidentifier must be a UUID") { isUuid(it.getClaimAsString(UserClaims.OBJECT_IDENTIFIER)) },
        )

    fun internalClient(): OAuth2TokenValidator<Jwt> = DelegatingOAuth2TokenValidator(expiryRequired(), machineToken())

    fun sourceApplication(expectedClientId: String): OAuth2TokenValidator<Jwt> =
        DelegatingOAuth2TokenValidator(
            expiryRequired(),
            machineToken(),
            claim("sub is not the source application's client") { it.subject == expectedClientId },
        )

    /** NAM sets aud to the client that asked for the token, so aud is sub for client_credentials. */
    private fun machineToken(): OAuth2TokenValidator<Jwt> =
        claim("must be a client token") {
            it.subject != null && it.audience == listOf(it.subject) && !it.hasClaim(UserClaims.OBJECT_IDENTIFIER)
        }

    private fun expiryRequired(): OAuth2TokenValidator<Jwt> =
        JwtTimestampValidator().apply { setAllowEmptyExpiryClaim(false) }

    private fun claim(
        description: String,
        test: (Jwt) -> Boolean,
    ): OAuth2TokenValidator<Jwt> =
        OAuth2TokenValidator { jwt ->
            if (test(jwt)) {
                OAuth2TokenValidatorResult.success()
            } else {
                OAuth2TokenValidatorResult.failure(OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, description, null))
            }
        }

    // UUID.fromString also accepts short forms such as 1-1-1-1-1.
    private fun isUuid(value: String?): Boolean {
        if (value == null) return false
        return runCatching { UUID.fromString(value).toString() == value.lowercase() }.getOrDefault(false)
    }
}

/** The app's decoder, with [validator] run after it. */
internal fun JwtDecoder.validatedBy(validator: OAuth2TokenValidator<Jwt>): JwtDecoder =
    JwtDecoder { token ->
        val jwt = decode(token)
        val result = validator.validate(jwt)
        if (result.hasErrors()) {
            throw JwtValidationException(result.errors.mapNotNull { it.description }.joinToString(), result.errors)
        }
        jwt
    }
