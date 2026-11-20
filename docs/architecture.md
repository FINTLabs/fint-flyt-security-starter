# Architecture

C4 level 1 and 3 for flyt-security-starter. Blue is this library or the services that embed it, turquoise is
external.

flyt-security-starter is a Spring Boot library, not a deployed service. Every FLYT backend service embeds it to decide
who may call which route:

| Order | Chain              | Routes                                                        | Caller                   | Rule                                                                      |
| ----- | ------------------ | ------------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------- |
| 1     | Public             | `/actuator/health/**`, `/actuator/prometheus`, `public-paths` | Anyone                   | permitAll                                                                 |
| 2     | Internal client    | `/api/intern-klient/**`                                       | Other FLYT services      | Client token, `sub` in `authorized-client-ids`                            |
| 3     | User               | `/api/intern/**`                                              | FLYT users               | Access token for the FLYT login from an allowed organization, role `USER` |
| 4     | Source application | `external.paths`, e.g. `/api/acos/**`                         | The gateway's source app | Client token, `sub` is `expected-client-id`                               |
| 5     | Deny all           | Everything else, including other Actuator endpoints           | –                        | 401                                                                       |

## C4 level 1: System context

```mermaid
C4Context
    title System context for flyt-security-starter

    Person_Ext(user, "FLYT user", "Uses the FLYT frontend.")
    System_Ext(sourceApp, "Source application", "Acos and others.")
    System(service, "FLYT service", "Any FLYT backend service with flyt-security-starter.")
    System_Ext(otherService, "Other FLYT service", "Calls this service.")
    System_Ext(idp, "NAM", "Issues tokens, publishes JWKS.")
    System_Ext(authz, "authorization-service", "User access to source applications.")

    Rel(user, service, "Internal API", "HTTP")
    Rel(sourceApp, service, "External API", "HTTP")
    Rel(otherService, service, "Client API", "HTTP")
    Rel(service, idp, "Keys, tokens", "OIDC")
    Rel(service, authz, "User access", "HTTP")

    UpdateRelStyle(user, service, $textColor="#3B82F6", $lineColor="#3B82F6", $offsetX="10")
    UpdateRelStyle(sourceApp, service, $textColor="#3B82F6", $lineColor="#3B82F6", $offsetX="20")
    UpdateRelStyle(otherService, service, $textColor="#3B82F6", $lineColor="#3B82F6", $offsetX="-35", $offsetY="-30")
    UpdateRelStyle(service, idp, $textColor="#3B82F6", $lineColor="#3B82F6", $offsetX="10")
    UpdateRelStyle(service, authz, $textColor="#3B82F6", $lineColor="#3B82F6", $offsetX="20")
    UpdateElementStyle(service, $bgColor="#93C5FD", $fontColor="#1F2937", $borderColor="#3B82F6")
    UpdateElementStyle(user, $bgColor="#A5F3FC", $fontColor="#1F2937", $borderColor="#06B6D4")
    UpdateElementStyle(sourceApp, $bgColor="#A5F3FC", $fontColor="#1F2937", $borderColor="#06B6D4")
    UpdateElementStyle(otherService, $bgColor="#A5F3FC", $fontColor="#1F2937", $borderColor="#06B6D4")
    UpdateElementStyle(idp, $bgColor="#A5F3FC", $fontColor="#1F2937", $borderColor="#06B6D4")
    UpdateElementStyle(authz, $bgColor="#A5F3FC", $fontColor="#1F2937", $borderColor="#06B6D4")
    UpdateLayoutConfig($c4ShapeInRow="2", $c4BoundaryInRow="1")
```

The service validates every token with the keys NAM publishes. Only `FlytAccess` calls authorization-service, with a
`client_credentials` token from NAM. Source applications are checked locally against the gateway's own client ID.

## C4 level 3: Components

```mermaid
C4Component
    title Components in flyt-security-starter

    Component_Ext(caller, "Caller", "HTTP", "User, FLYT service or source app.")
    Component(chains, "Filter chains", "Spring Security", "One per caller type, deny-all last.")
    Component(validators, "Token checks", "JwtDecoder, validators", "Spring defaults plus checks per chain.")
    Component(roles, "Roles", "UserRoleResolver, RoleHierarchy", "Capped per organization.")
    Component_Ext(controllers, "Controllers", "The app", "@PreAuthorize")
    Component(access, "FlytAccess", "RestClient, OAuth2", "@flyt, one call per request.")
    Component_Ext(authz, "authorization-service", "Spring Boot", "Source application IDs per user.")

    Rel(caller, chains, "Bearer")
    Rel(chains, validators, "Decode")
    Rel(chains, roles, "Users")
    Rel(roles, controllers, "Roles")
    Rel(controllers, access, "Check")
    Rel(access, authz, "GET", "HTTP")

    UpdateRelStyle(caller, chains, $textColor="#3B82F6", $lineColor="#3B82F6", $offsetX="-35", $offsetY="-30")
    UpdateRelStyle(chains, validators, $textColor="#3B82F6", $lineColor="#3B82F6", $offsetX="20")
    UpdateRelStyle(chains, roles, $textColor="#3B82F6", $lineColor="#3B82F6", $offsetX="10")
    UpdateRelStyle(roles, controllers, $textColor="#3B82F6", $lineColor="#3B82F6", $offsetX="20")
    UpdateRelStyle(controllers, access, $textColor="#3B82F6", $lineColor="#3B82F6", $offsetX="-35", $offsetY="-30")
    UpdateRelStyle(access, authz, $textColor="#3B82F6", $lineColor="#3B82F6", $offsetX="20")
    UpdateElementStyle(chains, $bgColor="#93C5FD", $fontColor="#1F2937", $borderColor="#3B82F6")
    UpdateElementStyle(validators, $bgColor="#93C5FD", $fontColor="#1F2937", $borderColor="#3B82F6")
    UpdateElementStyle(roles, $bgColor="#93C5FD", $fontColor="#1F2937", $borderColor="#3B82F6")
    UpdateElementStyle(access, $bgColor="#93C5FD", $fontColor="#1F2937", $borderColor="#3B82F6")
    UpdateElementStyle(caller, $bgColor="#A5F3FC", $fontColor="#1F2937", $borderColor="#06B6D4")
    UpdateElementStyle(controllers, $bgColor="#A5F3FC", $fontColor="#1F2937", $borderColor="#06B6D4")
    UpdateElementStyle(authz, $bgColor="#A5F3FC", $fontColor="#1F2937", $borderColor="#06B6D4")
    UpdateLayoutConfig($c4ShapeInRow="2", $c4BoundaryInRow="1")
```

- **Token checks:** each chain wraps the app's `JwtDecoder` (signature, time and issuer, from Spring Boot) with its own
  `DelegatingOAuth2TokenValidator`. `exp` is required in every chain. A failed check gives 401.
- **User chain:** access token only (`scope` present, no `nonce` or `at_hash`), `aud` is the FLYT login client,
  `organizationid` is a tenant or operator organization, and `objectidentifier` is a UUID.
- **Client chains:** NAM sets `aud` to the client that asked for the token, so a client token has `aud` equal to
  `sub` and no `objectidentifier`.
- **Roles:** `roles` from the Vigo role catalog, capped at `tenant-max-role` (USER) for the tenant and
  `operator-max-role` (DEVELOPER) for operators. `RoleHierarchy`: DEVELOPER > ADMIN > USER.
- **FlytAccess:** `GET /api/intern-klient/authorization/users/{objectIdentifier}/source-application-ids`, once per
  request. `[]` for an unknown user. Errors and 404 give 503.
