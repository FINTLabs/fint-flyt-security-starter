package no.novari.flyt.security

/** FLYT roles in the Vigo role catalog, lowest first. The order is used to cap roles per organization. */
public enum class UserRole(
    public val claimValue: String,
) {
    USER("https://role-catalog.vigoiks.no/vigo/flyt/user"),
    ADMIN("https://role-catalog.vigoiks.no/vigo/flyt/admin"),
    DEVELOPER("https://role-catalog.vigoiks.no/vigo/flyt/developer"),
    ;

    public val authority: String get() = "ROLE_$name"

    public companion object {
        private val byClaimValue = entries.associateBy(UserRole::claimValue)

        public fun fromClaimValue(claimValue: String): UserRole? = byClaimValue[claimValue]
    }
}
