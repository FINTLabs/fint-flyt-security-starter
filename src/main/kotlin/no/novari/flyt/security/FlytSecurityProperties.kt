package no.novari.flyt.security

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("novari.flyt.security")
public class FlytSecurityProperties(
    public val tenant: Tenant = Tenant(),
    public val roles: Roles = Roles(),
    public val user: User = User(),
    public val internalClient: InternalClient = InternalClient(),
    public val external: External = External(),
    public val publicPaths: List<String> = emptyList(),
    public val authorization: Authorization = Authorization(),
) {
    init {
        publicPaths.forEach { path ->
            require(path.startsWith("/")) { "novari.flyt.security.public-paths: '$path' must start with /" }
            // Only exact routes may be public under /api, so a pattern cannot open a protected route by accident.
            val canMatchApi = path.startsWith("/api") || isPattern(firstSegment(path))
            require(!(isPattern(path) && canMatchApi)) {
                "novari.flyt.security.public-paths: '$path' is a pattern that can match routes under /api"
            }
        }
        if (user.audience != null) {
            require(user.audience.isNotBlank()) { "novari.flyt.security.user.audience must not be blank" }
            require(tenant.orgIds.isNotEmpty()) { "novari.flyt.security.tenant.org-ids must be set (fint.org-id)" }
        }
        external.validate()
    }

    internal val tenantOrgIds: Set<String>
        get() = (tenant.orgIds + tenant.additionalOrgIds).toSet()

    public class Tenant(
        public val orgIds: List<String> = emptyList(),
        public val additionalOrgIds: List<String> = emptyList(),
    )

    public class Roles(
        public val tenantMaxRole: UserRole = UserRole.USER,
        public val operatorOrgIds: List<String> = emptyList(),
        public val operatorMaxRole: UserRole = UserRole.DEVELOPER,
    )

    /** The user chain is only registered when [audience] is set. */
    public class User(
        public val audience: String? = null,
    )

    public class InternalClient(
        public val authorizedClientIds: List<String> = emptyList(),
    )

    /**
     * The source application chain is only registered when [sourceApplication] is set. The expected client ID is read
     * from [SourceApplication.clientIdProperty].
     */
    public class External(
        public val paths: List<String> = emptyList(),
        public val sourceApplication: SourceApplication? = null,
    ) {
        internal fun validate() {
            if (paths.isEmpty() && sourceApplication == null) return
            val prefix = "novari.flyt.security.external"
            require(sourceApplication != null) { "$prefix.source-application must be set, e.g. ACOS" }
            require(paths.isNotEmpty()) { "$prefix.paths must list the gateway's routes, e.g. /api/acos/**" }
            paths.forEach { path ->
                val segments = path.removePrefix("/").split('/')
                require(segments.size >= 2 && segments[0] == "api" && !isPattern(segments[1])) {
                    "$prefix.paths: '$path' must be an explicit route under /api, e.g. /api/acos/**"
                }
                require(!segments[1].startsWith("intern")) { "$prefix.paths: '$path' is an internal route" }
            }
        }
    }

    public class Authorization(
        // flyt-security-defaults.yml adds the host app's context path.
        public val baseUrl: String = "http://fint-flyt-authorization-service:8080",
    )

    private companion object {
        fun isPattern(path: String): Boolean = path.any { it == '*' || it == '?' || it == '{' }

        fun firstSegment(path: String): String = path.removePrefix("/").substringBefore('/')
    }
}
