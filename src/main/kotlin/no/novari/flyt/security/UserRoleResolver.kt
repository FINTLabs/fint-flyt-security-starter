package no.novari.flyt.security

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt

/**
 * Gives the roles of a validated user token as `ROLE_*` authorities. `RoleHierarchy` adds the implied roles.
 *
 * Replace the bean to take roles from somewhere else, e.g. county administrators or SCIM.
 */
public fun interface UserRoleResolver {
    public fun resolve(jwt: Jwt): Collection<GrantedAuthority>
}

/** Roles from the `roles` claim, capped by the highest role the user's organization may have. */
internal class PolicyUserRoleResolver(
    private val properties: FlytSecurityProperties,
) : UserRoleResolver {
    override fun resolve(jwt: Jwt): Collection<GrantedAuthority> {
        val maxRole = maxRole(jwt.getClaimAsString(UserClaims.ORGANIZATION_ID)) ?: return emptySet()
        return jwt
            .getClaimAsStringList(UserClaims.ROLES)
            .orEmpty()
            .mapNotNull(UserRole::fromClaimValue)
            .map { minOf(it, maxRole) }
            .mapTo(mutableSetOf()) { SimpleGrantedAuthority(it.authority) }
    }

    private fun maxRole(organizationId: String?): UserRole? =
        listOfNotNull(
            properties.roles.tenantMaxRole.takeIf { organizationId in properties.tenantOrgIds },
            properties.roles.operatorMaxRole.takeIf { organizationId in properties.roles.operatorOrgIds },
        ).maxOrNull()
}

internal object UserClaims {
    const val ORGANIZATION_ID = "organizationid"
    const val OBJECT_IDENTIFIER = "objectidentifier"
    const val ROLES = "roles"
}
