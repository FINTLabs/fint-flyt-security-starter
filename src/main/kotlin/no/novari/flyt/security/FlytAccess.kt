package no.novari.flyt.security

import org.springframework.http.HttpStatus
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.client.RestClient
import org.springframework.web.client.body
import org.springframework.web.context.request.RequestAttributes
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.server.ResponseStatusException

/**
 * The current user's access to source applications, registered as `@flyt`:
 * `@PreAuthorize("@flyt.hasSourceApplication(#sourceApplicationId)")`.
 *
 * Fetches the user's source applications from authorization-service the first time it is used in a request, and reuses
 * them for the rest of the request.
 */
public class FlytAccess internal constructor(
    private val restClient: RestClient,
) {
    public fun sourceApplicationIds(): Set<Long> {
        val request = RequestContextHolder.getRequestAttributes() ?: return fetch()
        @Suppress("UNCHECKED_CAST")
        (request.getAttribute(REQUEST_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST) as Set<Long>?)?.let { return it }
        return fetch().also { request.setAttribute(REQUEST_ATTRIBUTE, it, RequestAttributes.SCOPE_REQUEST) }
    }

    public fun hasSourceApplication(sourceApplicationId: Long): Boolean = sourceApplicationId in sourceApplicationIds()

    private fun fetch(): Set<Long> {
        val objectIdentifier =
            (SecurityContextHolder.getContext().authentication as? JwtAuthenticationToken)
                ?.token
                ?.getClaimAsString(UserClaims.OBJECT_IDENTIFIER)
                ?: throw AccessDeniedException("Source application access requires a user")
        // authorization-service gives [] for an unknown user, so 404 means the route is missing, not "no access".
        return try {
            restClient
                .get()
                .uri("/users/{objectIdentifier}/source-application-ids", objectIdentifier)
                .retrieve()
                .body<Set<Long>>()
                ?: error("authorization-service returned an empty response")
        } catch (exception: Exception) {
            throw ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Unable to verify user access", exception)
        }
    }

    private companion object {
        val REQUEST_ATTRIBUTE: String = FlytAccess::class.java.name + ".sourceApplicationIds"
    }
}
