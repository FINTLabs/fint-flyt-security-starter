# fint-flyt-security-starter

Spring Boot auto-configuration (servlet stack) that secures FLYT services with standard Spring Security 7: one filter
chain per caller type, JWT validators per chain, roles through `RoleHierarchy`, and method security with
`@PreAuthorize`. Replaces `fint-flyt-web-resource-server`.

```kotlin
implementation("no.novari:flyt-security-starter:1.0.0")
```

See [docs/architecture.md](docs/architecture.md) for C4 diagrams.

## Filter chains

| Order | Routes                                                        | Caller                   | Extra checks (401 if not met)                                                                                                           | Authorization                           |
| ----- | ------------------------------------------------------------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| 1     | `/actuator/health/**`, `/actuator/prometheus`, `public-paths` | Anyone                   | –                                                                                                                                       | permitAll                               |
| 2     | `/api/intern-klient/**`                                       | Other FLYT service       | Client token (`aud` is `sub`, no `objectidentifier`)                                                                                    | `sub` in `authorized-client-ids`, 403   |
| 3     | `/api/intern/**`                                              | FLYT user                | Access token (`scope`, no `nonce`/`at_hash`), `aud` is `user.audience`, `organizationid` is tenant or operator, `objectidentifier` UUID | `hasRole('USER')`, then `@PreAuthorize` |
| 4     | `external.paths`, e.g. `/api/acos/**`                         | The gateway's source app | Client token, `sub` is `external.expected-client-id`                                                                                    | `SOURCE_APPLICATION_ID_<id>`            |
| 5     | Everything else                                               | –                        | –                                                                                                                                       | 401                                     |

Every chain decodes with the app's `JwtDecoder` from Spring Boot (signature, time and issuer) and requires `exp`. The
user chain is only registered when `user.audience` is set, and the source application chain only when
`external.expected-client-id` is set. Otherwise their routes fall through to deny-all.

## Roles

Roles come from the `roles` claim (Vigo role catalog) and are capped per organization:

| Organization                                                | Highest role                          |
| ----------------------------------------------------------- | ------------------------------------- |
| Tenant: `fint.org-id` and `tenant.additional-org-ids`       | `roles.tenant-max-role` (USER)        |
| Operator: `roles.operator-org-ids` (`vigo.no`, `novari.no`) | `roles.operator-max-role` (DEVELOPER) |
| Anything else                                               | Rejected with 401                     |

`RoleHierarchy` gives DEVELOPER > ADMIN > USER, so `hasRole('ADMIN')` passes for DEVELOPER. Replace the
`UserRoleResolver` bean to take roles from somewhere else.

## Access to source applications

`FlytAccess` is the bean `flyt`. It fetches the user's source applications from authorization-service the first time it
is used in a request, and reuses them for the rest of the request:

```kotlin
@PreAuthorize("@flyt.hasSourceApplication(#sourceApplicationId)")
fun get(@PathVariable sourceApplicationId: Long): Integration = ...

fun list(): List<Integration> = repository.findAllBySourceApplicationIdIn(flyt.sourceApplicationIds())
```

It calls `GET /api/intern-klient/authorization/users/{objectIdentifier}/source-application-ids` (FFS-2429), which gives
`[]` for an unknown user. Errors and 404 give 503. Calls to authorization-service and the token request to NAM time out
after 2s connect and 5s read, unless the app sets `spring.http.clients.connect-timeout` or `read-timeout`.

`FlytAccess` needs the OAuth2 client registration `authorization-service`:

```yaml
spring:
  security:
    oauth2:
      client:
        provider:
          fint-idp:
            token-uri: https://idp.felleskomponent.no/nidp/oauth/nam/token
        registration:
          authorization-service:
            authorization-grant-type: client_credentials
            client-id: ${fint.flyt.authorization.sso.client-id}
            client-secret: ${fint.flyt.authorization.sso.client-secret}
            provider: fint-idp
```

On the external routes, `authentication.sourceApplicationId()` gives the gateway's source application.

## Configuration

| Property                                                     | Default                                                      | Description                                                                                                      |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `novari.flyt.security.tenant.org-ids`                        | `${fint.org-id}`                                             | The namespace's organization, set by flaiserator.                                                                |
| `novari.flyt.security.tenant.additional-org-ids`             | –                                                            | Extra tenant organizations (afk, bfk and ofk: `viken.no,frid-iks.no`).                                           |
| `novari.flyt.security.roles.tenant-max-role`                 | `USER`                                                       | Highest role for tenant users.                                                                                   |
| `novari.flyt.security.roles.operator-org-ids`                | `vigo.no,novari.no`                                          | Operator organizations.                                                                                          |
| `novari.flyt.security.roles.operator-max-role`               | `DEVELOPER`                                                  | Highest role for operator users.                                                                                 |
| `novari.flyt.security.user.audience`                         | –                                                            | `fint.sso.client-id` from the secret `fint-flyt-auth-forward-sso`. Turns on the user chain.                      |
| `novari.flyt.security.internal-client.authorized-client-ids` | `${fint.flyt.authorization.sso.client-id}`                   | Clients allowed on `/api/intern-klient/**`.                                                                      |
| `novari.flyt.security.external.paths`                        | –                                                            | The gateway's routes, explicit under `/api` (e.g. `/api/acos/**`). `/api/**` and `/api/intern*` fail at startup. |
| `novari.flyt.security.external.source-application-id`        | –                                                            | The gateway's source application. Replaced by a `SourceApplication` registry after the Acos pilot (FFS-2430).    |
| `novari.flyt.security.external.expected-client-id`           | –                                                            | The source application's client ID. Turns on the source application chain.                                       |
| `novari.flyt.security.public-paths`                          | –                                                            | Exact Swagger routes. Patterns that can match `/api` (e.g. `/api/**`, `/**`) fail at startup.                    |
| `novari.flyt.security.authorization.base-url`                | `http://fint-flyt-authorization-service:8080` + context path | authorization-service.                                                                                           |
| `spring.security.oauth2.resourceserver.jwt.issuer-uri`       | `https://idp.felleskomponent.no/nidp/oauth/nam`              | NAM.                                                                                                             |

Set `user.audience` with `env`, not `envFrom`. The secret exposes `fint.sso.*`, which collides with other OAuth clients
in the pod:

```yaml
# kustomize/base/flais.yaml, under spec.env
- name: novari.flyt.security.user.audience
  valueFrom:
    secretKeyRef:
      name: fint-flyt-auth-forward-sso
      key: fint.sso.client-id
```

## Migrating from fint-flyt-web-resource-server 5

**Dependency and package:** `no.novari:flyt-web-resource-server` is `no.novari:flyt-security-starter`, and
`no.novari.flyt.webresourceserver` is `no.novari.flyt.security`.

**Configuration:**

| fint-flyt-web-resource-server 5                                                           | flyt-security-starter                                                                               |
| ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `novari.flyt.web-resource-server.security.api.*.enabled`                                  | Remove. The chains follow from the properties below.                                                |
| `novari.flyt.web-resource-server.security.api.internal.authorized-org-id-role-pairs-json` | Remove from all overlays. Set `user.audience`, and `tenant.additional-org-ids` in afk, bfk and ofk. |
| `novari.flyt.web-resource-server.security.api.internal-client.authorized-client-ids`      | `novari.flyt.security.internal-client.authorized-client-ids`, or remove to use the default.         |
| `novari.flyt.web-resource-server.security.api.external.authorized-source-application-ids` | `external.paths`, `external.source-application-id` and `external.expected-client-id`.               |
| `novari.flyt.web-resource-server.security.authorization.*`                                | `novari.flyt.security.authorization.*`                                                              |

**Code:**

| fint-flyt-web-resource-server 5                                              | flyt-security-starter                                                         |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `UserAuthorizationService.checkIfUserHasAccessToSourceApplication(auth, id)` | `@PreAuthorize("@flyt.hasSourceApplication(#id)")`                            |
| `UserAuthorizationService.getUserAuthorizedSourceApplicationIds(auth, ids)`  | `ids intersect flyt.sourceApplicationIds()`                                   |
| `UserAuthorizationService.userHasRole(auth, role)`                           | `@PreAuthorize("hasRole('ADMIN')")`                                           |
| `SourceApplicationAuthorizationService.getSourceApplicationId(auth)`         | `auth.sourceApplicationId()`                                                  |
| `AuthorityMappingService`, `AuthorityPrefix`                                 | `SourceApplicationAuthority.of(id)`, `UserRole.authority`                     |
| `SecurityFilterChainFactoryService` (Swagger chains)                         | `novari.flyt.security.public-paths`                                           |
| `UrlPaths.INTERNAL_ADMIN_API`                                                | Routes under `UrlPaths.INTERNAL_API` with `@PreAuthorize("hasRole('ADMIN')")` |
| `UserRole.getUserRoleFromValue(value)`                                       | `UserRole.fromClaimValue(value)`. The order is now USER, ADMIN, DEVELOPER.    |

`Authentication` no longer needs to be passed through the controllers: `FlytAccess` reads it from the
`SecurityContextHolder`.

**Behaviour:**

- User tokens issued to another client, ID tokens and tokens without `exp` give 401.
- A user from an organization outside the tenant and operators gets 401, not 403.
- Tenant users are capped at USER: an ADMIN or DEVELOPER claim from the tenant gives USER.
- The external API is no longer `/api/**` for every known source application. Only the gateway's explicit routes and
  its own client are allowed. There is no lookup in authorization-service.
- The `fint-flyt-authorization-oauth2-client` registration is only needed for `FlytAccess`.
- Caffeine is no longer brought in.
- A Swagger UI under `/api` (eapply) must list exact routes in `public-paths`, or move out of `/api`.

**Tests:** mocks of `SourceApplicationAuthorizationClient`, `UserAuthorizationClient` and `JwtDecoder` go away. Use
signed tokens through the real `JwtDecoder` as in
[TestTokens](src/test/kotlin/no/novari/flyt/security/support/TestTokens.kt), or mock `FlytAccess` with
`@MockitoBean(name = "flyt")`.

## Development

Requires Java 25+. The library is compiled for Java 21.

```shell
./gradlew check               # tests, ktlint and the ABI check
./gradlew publishToMavenLocal # try it in an app
```

HTTP tests sign tokens with a test JWK made at startup and served as `jwk-set-uri`, so they go through Spring Boot's
`JwtDecoder` and the real chains.

### Dependency locking

Versions are locked in `gradle.lockfile` and `settings-gradle.lockfile`. Dependabot updates them in its own PRs. After a
change by hand that affects dependency resolution, run `./gradlew dependencies --write-locks` and commit the lockfiles.
The Spring Boot BOM is only used inside the build. The published POM has resolved versions and no BOM, so the library
does not change the app's Spring Boot or Kotlin version.

### Locked API

The public API is locked in `api/flyt-security-starter.api` with
[binary-compatibility-validator](https://github.com/Kotlin/binary-compatibility-validator), because
fint-flyt-gateway-starter is compiled against one version while the app may pull in a newer one. After an intended
change, run `./gradlew apiDump` and commit the dump. Removed or changed lines need a new major, new lines a new minor.
`explicitApi()` is on, so keep what apps do not use `internal`.
