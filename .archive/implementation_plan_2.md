# Implementation plan: Password storage, signing keys / JWS / JWT, tokens, registered clients + admin API and resource server (issue #2)

## Task summary

Make the `auth-server` credential and token core production-shaped and give `resource-server` a real protected API:
Argon2id password storage with upgrade on login and a compromised-password check, account registration / password
change / reset, persisted and rotating signing keys, a `JwtEncoder`-based JWT service, token customisation (roles,
tenant, audience), UserInfo, revocation, refresh-token reuse detection, expired-authorization clean-up, registered
client management (seeding + admin API + optional dynamic registration) and the resource server API
(read + sensitive delete, authority conversion, method security, introspection profile, RFC 6750 errors).

Source: GitHub issue #2
Base branch: main
Flyway range: `V200`–`V299` only.

Choices made (challenge them in review):
- **Hexagonal fit.** `application` may not use Spring Security, so the use cases talk to domain ports
  (`PasswordHasher`, `CompromisedPasswordCheck`, `SigningKeyRepository`, `SigningKeyGenerator`, `SignedTokenService`,
  `AccountMailer`, `UserAuthorizationRepository`, `ClientRegistrationRepository`). `PasswordEncoder`,
  `HaveIBeenPwnedRestApiPasswordChecker`, Nimbus and AES-GCM live in `api/web` or `infrastructure/*`. JDBC stays in
  `infrastructure/persistence`; `infrastructure/keys` reaches the key table only through an application use case
  (adapters may not depend on each other).
- **Single-use tokens.** The e-mail-verification token is a signed JWT (issue asks for it); the password-reset token is a
  random opaque value stored hashed in an `account_tokens` table in this range (#6 will not have merged).
- **Signing vs. publishing keys.** Two beans: `JWKSource` (public JWKS: `active` + `next` + still-valid `retired`) and a
  `JwtEncoder` bean over an *active-only* private source, so signing never has to choose between several keys.
  Spring Authorization Server picks a `JwtEncoder` bean when present.
- **Encrypted private keys.** `Encryptors.stronger` (AES-256-GCM) with `authserver.keys.encryption.password` / `.salt`
  from configuration (environment in production). In the `dev` profile a per-machine random secret is created once under
  `~/.irurueta-auth-server/` and reused, so persisted keys stay decryptable across restarts and nothing is committed.
  The e2e harness passes its own random values.
- **Rotation is ShedLock-ready, not ShedLock-dependent.** Rotation runs inside one transaction guarded by a PostgreSQL
  advisory lock, so two instances cannot both rotate; the scheduled method is a thin, annotation-ready entry point.
- **Audience model.** `aud` is the logical API identifier configured per client (client setting `audiences`, default
  `[clientId]`), and `resource-server` requires `resource-server` (property `RESOURCE_SERVER_AUDIENCES`, no longer
  `bff`). Seeded `bff` and `spa-public` carry `audiences: [resource-server]`.
- **Tenant.** A `tenant` column on `users` (default `default`) feeds the `tenant` claim.
- **Claim extension point.** `JwtClaimsContributor` beans (ordered) are applied by the token customizer, so #4 adds
  `amr` / `acr` / `auth_time` without editing it. A `ProtocolChainCustomizer` extension point (same idea as
  `LoginChainCustomizer`) lets features configure the protocol endpoints (UserInfo mapper, dynamic registration)
  without editing `SecurityConfig` again.
- **Admin / account API security.** A dedicated `/api/**` chain validates bearer JWTs issued by this server itself
  (`jwtDecoder(jwkSource)`); `/api/admin/**` needs scope `admin` or role `ROLE_ADMIN`; register and reset are public.
- **Refresh-token reuse detection.** A decorator over `OAuth2AuthorizationService` records the hash of each rotated-out
  refresh token (`consumed_refresh_tokens`); presenting one revokes the whole authorization.
- **Default clients.** `DefaultClientDefinitions` (application layer) is the single definition of `bff` and `spa-public`,
  used by the idempotent `ClientSeeder` (secrets from environment, never committed) and by `DevDataInitializer`
  (generated, logged dev secret, as today).
- **Dynamic client registration** (`/connect/register`) is supported by Spring Authorization Server, so it is included,
  off by default (`authserver.oidc.client-registration.enabled`), requiring an initial access token with scope
  `client.create`.
- **Resource-server domain.** A `Document` (id, title, owner) with a read and a delete use case; the driven adapter is
  an in-memory repository (`infrastructure/memory`), a real adapter that needs no schema in this range.
- **Compromised-password check** is on by default and off in tests / dev profile through a property; tests mock the port.

Open clarifications: none

## Acceptance criteria coverage

| # | Criterion | Covered by tasks |
|---|---|---|
| 1 | "All scope items are implemented and tested. `./mvnw verify` green. The tags for the docs pages are listed in the PR." | Task 1–Task 36 |
| 2 | derived: a `{bcrypt}` user is upgraded to `{argon2}` after login; the compromised-password check is mocked | Task 3, Task 17, Task 26 |
| 3 | derived: registration with e-mail verification, password change and reset work and are timing-safe for unknown users | Task 4, Task 9, Task 13, Task 18, Task 27 |
| 4 | derived: key rotation keeps old tokens valid until retirement and JWKS matches each state | Task 5, Task 10, Task 12, Task 19, Task 28 |
| 5 | derived: custom claims, refresh rotation, reuse detection, revocation and introspection active / inactive behave | Task 6, Task 11, Task 21, Task 29 |
| 6 | derived: registered clients are seeded idempotently with encoded secrets and managed through the admin API | Task 7, Task 11, Task 20, Task 22, Task 30 |
| 7 | derived: the resource server enforces audience and scopes (`jwt()` slice tests plus one end-to-end test with a real token) | Task 14, Task 23, Task 24, Task 25, Task 31, Task 32 |
| 8 | derived: committed OpenAPI documents are regenerated by drift tests | Task 33 |

## Current code state

- Java 21, Spring Boot 4.1.2, Maven reactor, hexagonal modules per application (enforcer `bannedDependencies` per module
  + ArchUnit `HexagonalArchitectureTest` in each `boot`). `application` bans `org.springframework.security:*`;
  `api/web` bans `infrastructure-*` and JDBC; `infrastructure/*` ban `api-*` and sibling `infrastructure-*`.
- **auth-server domain** `domain.password`: `UserAccount` record (`id, username, encodedPassword, enabled, authorities`),
  `UserAccountRepository.findByUsername`. **application** `application.password.FindUserAccountUseCase`.
  **api/web**: `SecurityConfig` (two chains: protocol `@Order(1)`, login `@Order(2)`, `LoginChainCustomizer` extension
  point), `password.PasswordConfiguration` (`// TEMPORARY: replaced in #2` delegating encoder),
  `password.UserAccountUserDetailsService`, `OpenApiConfig` (group `/api/**`), `login.*`.
  Feature placeholder packages with `package-info.java`: `account`, `admin`, `clients`, `keys`, `tokens`, ...
- **infrastructure/persistence**: `V100` (SAS schema), `V101` (`users`, `user_authorities`, `user_passwords`),
  `JdbcUserAccountRepository`, `clients.JdbcAuthorizationServerConfiguration` (JDBC client / authorization / consent
  services), `dev.DevDataInitializer` (demo user + generated-secret `bff` client, dev profile).
- **infrastructure/keys**: `TemporaryJwkConfiguration` (`// TEMPORARY: replaced in #2`, in-memory RSA); deps
  `spring-context`, `spring-security-oauth2-jose` only.
- **boot**: `application.yml` (datasource, Flyway, issuer), `application-dev.yml` (docker compose, mail on localhost:1025;
  `compose.yaml` already has `postgres` and `mailpit`), ITs: `AuthorizationCodePkceIT`, `JdbcServicesIT`,
  `SecurityConfigIT`, `SecurityIT`, `OpenApiDriftIT`, `DevDataInitializerIT`, `HexagonalArchitectureTest`.
- **resource-server**: only `api/web` (`security.SecurityConfig`: JWT chain, everything authenticated except health) and
  `boot` (`application.yml` with `issuer-uri` and `audiences: bff`; test-only `ProtectedTestController`). No `domain`,
  `application` or `infrastructure` module yet.
- `e2e-tests`: `ManagedApp`, `SignInSmokeIT` (Playwright, packaged jars, credentials read from dev log lines).
- `docs/antora.yml` has one Collector scan per module (a new module needs a new scan). `openapi/auth-server.json` is the
  only committed OpenAPI document.
- Precedent: `.archive/implementation_plan_1.md` (walking skeleton) for structure and conventions.

## Implementation steps

### Group 1: Build wiring (Parallelizable: no — Task 2 edits the root `pom.xml` and `docs/antora.yml` that Task 1 also touches)

- [x] Task 1. Add dependencies _(java-springboot)_
  - [x] Task 1.1. `auth-server/api/web/pom.xml`: `org.bouncycastle:bcprov-jdk18on` (Argon2), `spring-security-oauth2-resource-server` /
    `spring-boot-starter-security-oauth2-resource-server` (bearer validation of the `/api/**` chain), `spring-boot-starter-validation`.
  - [x] Task 1.2. `auth-server/infrastructure/keys/pom.xml`: `auth-server-domain`, `auth-server-application`,
    `spring-security-crypto`; keep the enforcer rules. `auth-server/infrastructure/persistence/pom.xml`: `auth-server-application`.
  - [x] Task 1.3. Declare every new version in the root `pom.xml` (`dependencyManagement` / properties); no versions in modules.
  - [x] Task 1.4. Verify with `./mvnw -B -ntp -q -DskipTests verify` that enforcer and ArchUnit still pass.
- [x] Task 2. Create the new modules _(java-springboot)_
  - [x] Task 2.1. `auth-server/infrastructure/mail` (`auth-server-infrastructure-mail`: `spring-boot-starter-mail`, domain,
    application; same enforcer rules as `keys`), added to `infrastructure/pom.xml`, root `dependencyManagement`, `boot/pom.xml`
    and `docs/antora.yml`.
  - [x] Task 2.2. `resource-server/domain`, `resource-server/application`, `resource-server/infrastructure/memory`
    (aggregator `infrastructure/pom.xml` + module), with the enforcer rules of the table in `CLAUDE.md`; wire into
    `resource-server/pom.xml`, `api/web` and `boot` poms, root `dependencyManagement`, `docs/antora.yml` scans.
  - [x] Task 2.3. Update `resource-server`'s `HexagonalArchitectureTest` for the new layers and add `package-info.java` per package.
  - Group 1 outcome: poms only (root pom adds `bouncycastle.version` 1.85.2 and the new modules to `dependencyManagement`; `coverage` pom and `docs/antora.yml` scans extended). New modules `auth-server-infrastructure-mail`, `resource-server-domain`, `resource-server-application`, `resource-server-infrastructure-memory` (+ aggregator) each with `package-info.java` and enforcer rules. `HexagonalArchitectureTest` (resource-server) gained `INNER_LAYERS_NEVER_DEPEND_ON_ADAPTERS`. `./mvnw -B -ntp -DskipTests verify` green (Checkstyle, PMD, CPD, SpotBugs, enforcer); both `HexagonalArchitectureTest`s pass. No new code classes, so no new coverage.

### Group 2: Domain and application (Parallelizable: yes — one feature package per task, no shared file)

- [x] Task 3. Password core _(java-springboot)_
  - [x] Task 3.1. `domain.password`: `PasswordPolicy` (NIST style: min 12, max 128, no composition rules, rejects the username),
    ports `PasswordHasher` (`encode`, `matches`, `upgradeEncoding`) and `CompromisedPasswordCheck`; extend `UserAccountRepository`
    (`save`, `updatePassword`, `existsByUsername`, `findByEmail`, `markEmailVerified`); add `email`, `emailVerified`, `tenant`
    to `UserAccount` (compact constructor validation). Update `UserAccountTest`, add `PasswordPolicyTest`.
  - [x] Task 3.2. `application.password`: `UpgradePasswordHashUseCase` (stores a re-encoded hash after login). Tests with Mockito.
  - [x] Task 3.3. Wrap in tags `password-policy`, `password-upgrade`.
- [x] Task 4. Account use cases _(java-springboot)_
  - [x] Task 4.1. `domain.account`: `AccountToken` (`id, userId, purpose, hashedToken, expiresAt, usedAt`), ports
    `AccountTokenRepository` (store, `consume` atomically single-use, delete expired), `AccountMailer`, `SignedTokenService`
    (`issue(subject, purpose, ttl)`, `verify(token, purpose)`), `TokenGenerator`.
  - [x] Task 4.2. `application.account`: `RegisterAccountUseCase` (validates policy, runs compromised check, hashes, creates a
    disabled/unverified account, mails a verification JWT; an already-registered address gets a neutral "already registered"
    mail and the *same* hashing work, so the response and timing never reveal existence), `VerifyEmailUseCase`,
    `ChangePasswordUseCase` (checks current password, policy + compromised check, stores hash, calls
    `RevokeUserAuthorizationsUseCase`), `RequestPasswordResetUseCase` (always succeeds; unknown e-mail does equal work),
    `ResetPasswordUseCase` (single-use token, policy, revoke authorizations).
  - [x] Task 4.3. Mockito unit tests for every use case, including unknown-user paths and token reuse. Tags `account-register`,
    `account-reset`.
- [x] Task 5. Signing-key use cases _(java-springboot)_
  - [x] Task 5.1. `domain.keys`: `SigningKey` (`kid, alg, publicJwk, encryptedPrivateJwk, status, createdAt, activatedAt,
    retiredAt`), `SigningKeyStatus` (`NEXT, ACTIVE, RETIRED`), ports `SigningKeyRepository` (with a `withRotationLock` method),
    `SigningKeyGenerator`.
  - [x] Task 5.2. `application.keys`: `RotateSigningKeysUseCase` (bootstrap creates `active` + `next`; rotation promotes
    `next`→`active`, `active`→`retired`, creates a new `next`, deletes keys retired longer than the retention =
    max token TTL + skew; idempotent when called twice in a row), `ListSigningKeysUseCase`, `PublishedSigningKeysUseCase`
    (active + next + still-valid retired), `ActiveSigningKeyUseCase`. Inject a `Clock`.
  - [x] Task 5.3. Unit tests with a mocked `Clock` for each state transition. Tag `keys-rotation`.
- [x] Task 6. Token use cases _(java-springboot)_
  - [x] Task 6.1. `domain.tokens`: port `UserAuthorizationRepository` (`deleteByPrincipalName`, `deleteExpired(Instant)`).
  - [x] Task 6.2. `application.tokens`: `RevokeUserAuthorizationsUseCase`, `CleanExpiredAuthorizationsUseCase`; unit tests.
- [x] Task 7. Client use cases _(java-springboot)_
  - [x] Task 7.1. `domain.clients`: `ClientRegistration` (clientId, name, public/confidential, auth methods, grant types,
    redirect URIs, scopes, `requireProofKey`, `audiences`, access / refresh TTL, `accessTokenFormat`, `reuseRefreshTokens`),
    port `ClientRegistrationRepository` (`findByClientId`, `findAll`, `save`, `deleteByClientId`, `updateSecret`).
  - [x] Task 7.2. `application.clients`: `CreateClientUseCase` (returns the generated secret once, stores it encoded through
    `PasswordHasher`), `GetClientUseCase`, `ListClientsUseCase`, `UpdateClientUseCase`, `DeleteClientUseCase`,
    `RotateClientSecretUseCase`, `SeedRegisteredClientsUseCase` (idempotent), and `DefaultClientDefinitions` (`bff`:
    confidential, `client_secret_basic`, code + PKCE + refresh, rotation on; `spa-public`: public, PKCE, `none`).
  - [x] Task 7.3. Unit tests; tags `clients-seed`, `clients-admin`.
- [x] Task 8. Signed-token and mail ports documentation _(java-springboot)_
  - [x] Task 8.1. Javadoc the contract of `SignedTokenService` (reusable for client assertions in #8) and `AccountMailer` in
    `package-info.java` of `domain.account`; no code.
  - Group 2 outcome: domain + application only (plus a Jdbc touch-up), all unit-tested with Mockito; `./mvnw -B -ntp -o test` green for the whole reactor, `verify -DskipITs` (Checkstyle, PMD, CPD, SpotBugs, enforcer, ArchUnit) green for `auth-server/domain`, `application`, `infrastructure/persistence`; no class under 80% line coverage (unit only). Added `lombok.config` (`@Value` copyable, so `@RequiredArgsConstructor` serves the key use cases). Extra ports beyond the plan: `UserAccountRepository.findById` (reset flow), `domain.password` exceptions, `PasswordViolation`. `JdbcUserAccountRepository` implements `findById`, `existsByUsername`, `updatePassword`; `findByEmail`, `save`, `markEmailVerified` throw `UnsupportedOperationException` until Task 9 (needs the V200 columns). `ClientRegistrationRepository.save(registration, encodedSecret)` takes a `null` secret to keep the stored one. Spring-wired `*IT` tests in `boot` cannot start until Group 3 provides the adapters of the new ports (`PasswordHasher`, `SigningKeyRepository`, ...), integration tests were not run here.


### Group 3: Driven adapters (Parallelizable: yes — separate modules, or separate packages and migration files in `persistence`)

- [x] Task 9. Persistence: users and account tokens _(java-springboot)_
  - [x] Task 9.1. `V200__account.sql`: `users` gets `email` (unique, nullable for existing rows), `email_verified`, `tenant`
    (default `default`); new `account_tokens` table. Tags `account-schema`. (infrastructure/persistence: `V200__account.sql`; validated: unit-only coverage >=80% lines, Checkstyle/PMD/CPD/SpotBugs/enforcer/ArchUnit green.)
  - [x] Task 9.2. Extend `JdbcUserAccountRepository`; new `JdbcAccountTokenRepository` (`consume` as a single
    `UPDATE … WHERE used_at IS NULL AND expires_at > now() RETURNING`). Unit + `*IT` tests against PostgreSQL. (`JdbcUserAccountRepository` extended, new `account.JdbcAccountTokenRepository`, unit + `*IT` (green); validated.)
- [x] Task 10. Persistence: signing keys _(java-springboot)_
  - [x] Task 10.1. `V210__signing_keys.sql` (`kid`, `alg`, `public_jwk`, `private_jwk_encrypted`, `status`, timestamps; unique
    one `active`). Tag `keys-schema`. (`V210__signing_keys.sql`; validated: unit-only coverage >=80% lines, Checkstyle/PMD/CPD/SpotBugs/enforcer/ArchUnit green.)
  - [x] Task 10.2. `JdbcSigningKeyRepository` with `pg_advisory_xact_lock`-based `withRotationLock`; `*IT` test. (`keys.JdbcSigningKeyRepository`, unit + `*IT` (green, Testcontainers PostgreSQL); validated.)
- [x] Task 11. Persistence: clients and authorizations _(java-springboot)_
  - [x] Task 11.1. `JdbcClientRegistrationRepository` implementing the domain port over `JdbcRegisteredClientRepository`
    (maps `ClientRegistration` ⇄ `RegisteredClient`, `audiences` as a custom client setting, `TokenSettings` per client,
    `findAll` with `JdbcClient`). Unit + `*IT` tests. (`clients.JdbcClientRegistrationRepository`, unit + `*IT` (green, Testcontainers PostgreSQL); validated.)
  - [x] Task 11.2. `tokens.JdbcUserAuthorizationRepository` (`DELETE … WHERE principal_name`, expired clean-up covering all token
    columns). (`tokens.JdbcUserAuthorizationRepository`, unit + `*IT` (green, Testcontainers PostgreSQL); validated.)
  - [x] Task 11.3. `V230__consumed_refresh_tokens.sql` and `tokens.ReuseDetectingAuthorizationService` (decorator over the JDBC
    `OAuth2AuthorizationService`: records the hash of a rotated-out refresh token on `save`, revokes the authorization when a
    consumed token is presented in `findByToken`); register it in `JdbcAuthorizationServerConfiguration`. Tag
    `tokens-reuse-detection`. Unit + `*IT` tests. (`V230__consumed_refresh_tokens.sql`, `tokens.ReuseDetectingAuthorizationService`, registered in `JdbcAuthorizationServerConfiguration`; unit + `*IT` (green, Testcontainers PostgreSQL); validated.)
- [x] Task 12. Keys adapter _(java-springboot)_
  - [x] Task 12.1. Delete `TemporaryJwkConfiguration` and its test. Add `KeyEncryptionProperties` and `AesGcmKeyCipher`
    (`Encryptors.stronger`), `RsaSigningKeyGenerator` (implements `SigningKeyGenerator`, kid = random UUID, alg `RS256`).
    Tags `keys-encryption`. _Done in auth-server/infrastructure/keys (KeyEncryptionProperties, KeyEncryptionConfiguration, AesGcmKeyCipher, RsaSigningKeyGenerator; Temporary config removed); unit tests added; validated: unit-only coverage >=80% lines, Checkstyle/PMD/CPD/SpotBugs/enforcer/ArchUnit green._
  - [x] Task 12.2. `DatabaseJwkSourceConfiguration`: `JWKSource<SecurityContext>` over `PublishedSigningKeysUseCase` (public
    keys only, short in-memory cache refreshed on rotation) and the active-only signing source feeding a `JwtEncoder`
    bean. Tag `keys-jwk-source`. Test that exactly one key can sign while JWKS lists several. _Done (DatabaseJwkSourceConfiguration, CachedJwkSet); unit tests added; validated: unit-only coverage >=80% lines, Checkstyle/PMD/CPD/SpotBugs/enforcer/ArchUnit green._
  - [x] Task 12.3. `NimbusSignedTokenService` implementing `SignedTokenService` (`NimbusJwtEncoder` + `NimbusJwtDecoder` +
    `JwtValidators`: issuer, timestamps, purpose claim). Tag `jwt-service`. Tests: expired, wrong purpose, tampered. _Done (NimbusSignedTokenService); unit tests added; validated: unit-only coverage >=80% lines, Checkstyle/PMD/CPD/SpotBugs/enforcer/ArchUnit green._
  - [x] Task 12.4. `DevKeyEncryptionSecret` (`@Profile("dev")`, per-machine secret under `~/.irurueta-auth-server/`, Javadoc
    explains why it lives in `src/main`, like `DevDataInitializer`). _Done (DevKeyEncryptionSecret); unit tests added; validated: unit-only coverage >=80% lines, Checkstyle/PMD/CPD/SpotBugs/enforcer/ArchUnit green._
- [x] Task 13. Mail adapter _(java-springboot)_
  - [x] Task 13.1. `SmtpAccountMailer` (`JavaMailSender`, plain-text messages built from `MessageSource` with an explicit
    locale), mail properties in `application.yml`; unit test with a mocked `JavaMailSender`. Done in `auth-server/infrastructure/mail` (`SmtpAccountMailer`, `MailProperties`, `MailConfiguration`, bundle `mail/account-mail.properties`, 3 unit test classes) and `auth-server/boot` `application.yml`; validated: unit-only coverage >=80% lines, Checkstyle/PMD/CPD/SpotBugs/enforcer/ArchUnit green.
- [x] Task 14. Resource-server domain, application and memory adapter _(java-springboot)_
  - [x] Task 14.1. `domain.documents`: `Document` record, `DocumentRepository` port (`findByOwner`, `findAll`, `deleteById`,
    `save`).
  - [x] Task 14.2. `application.documents`: `ListDocumentsUseCase`, `DeleteDocumentUseCase` (with the comment marking where
    #4's `amr` check attaches).
  - [x] Task 14.3. `infrastructure.memory.InMemoryDocumentRepository` (concurrent map, empty at start); tests for all three — resource-server domain/application/infrastructure.memory; unit tests green; validated: unit-only coverage >=80% lines, Checkstyle/PMD/CPD/SpotBugs/enforcer/ArchUnit green.
  - Group 3 outcome: `./mvnw verify -DskipITs` green for the whole reactor; persistence `*IT`s (Testcontainers) green; unit-only line coverage >= 86% on every new class (DevKeyEncryptionSecret 87%, RsaSigningKeyGenerator 86%, JdbcClientRegistrationRepository 98%); boot Spring-wired `*IT`s not run (need Groups 4-5). `SecurityConfigIT` now uses its own runtime JWKSource instead of the deleted TemporaryJwkConfiguration.

### Group 4: Authorization-server plumbing (Parallelizable: yes — different files)

- [x] Task 15. Protocol chain extension point _(java-springboot)_
  - [x] Task 15.1. `api.web.ProtocolChainCustomizer` (`Customizer<OAuth2AuthorizationServerConfigurer>`), applied in order by
    `SecurityConfig.authorizationServerSecurityFilterChain` (one small edit). Test with a customizer bean. — ProtocolChainCustomizer + SecurityConfig edit; ordering covered in SecurityConfigIT (2 mock customizers); Checkstyle/PMD/SpotBugs/enforcer/ArchUnit green.
  - [x] Task 15.2. Describe it, and the `JwtClaimsContributor` point of Task 21, in `CLAUDE.md`. — done (extension-points section).
- [x] Task 16. API security chain _(java-springboot)_
  - [x] Task 16.1. `api.web.ApiSecurityConfig`: `@Order(0)` chain for `/api/**`, stateless, CSRF off, bearer JWT validated with
    the local `JwtDecoder`; public `POST /api/account/register`, `/api/account/password/reset`, `GET /api/account/verify`;
    `/api/admin/**` requires scope `admin` or `ROLE_ADMIN`; `JwtAuthenticationConverter` mapping `scope`/`roles`; RFC 6750
    errors. Tag `api-security`. Tests with `jwt()` in a `*IT` slice. — ApiSecurityConfig (+ ApiSecurityConfigTest converter unit tests, boot ApiSecurityConfigIT 10 tests); unit-only line coverage 54% (chain bean is framework wiring, covered by the IT slice: accepted exception); no new Checkstyle/PMD/SpotBugs issues. Note: SS7 adds a `FACTOR_BEARER` authority; SecurityConfigIT.protectedPage now sends `Accept: text/html` (non-HTML anonymous requests get 401 under SS 7).

### Group 5: Authorization-server features (Parallelizable: yes — one feature package each; Task 16 and 15 already landed)

- [x] Task 17. Password encoder and upgrade-on-login _(java-springboot)_ — api/web + application; unit tests added; validated in Group 5 (see outcome).
  - [x] Task 17.1. Replace `PasswordConfiguration` (remove the TEMPORARY marker): `DelegatingPasswordEncoder` with
    `argon2@SpringSecurity_v5_8` default (`Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()`), `bcrypt` and `pbkdf2`
    for legacy hashes. Tag `password-encoder`.
  - [x] Task 17.2. `SpringPasswordHasher` (implements `PasswordHasher`); `CompromisedPasswordCheck` adapter over
    `HaveIBeenPwnedRestApiPasswordChecker` with property `authserver.password.compromised-check.enabled`.
  - [x] Task 17.3. `UserAccountUserDetailsService` also implements `UserDetailsPasswordService` (calls
    `UpgradePasswordHashUseCase`); add `tenant`/email to mapped details. Tests: unit + the `{bcrypt}` → `{argon2}` assertion
    through a real login in Task 26.
- [x] Task 18. Account API _(java-springboot)_ — validated in Group 5
  - [x] Task 18.1. (auth-server/api/web; AccountController, AccountExceptionHandler, 4 request records, ApiSecurityConfig permits reset-request; unit tests added; validated) `api.web.account`: DTO records and `AccountController`: `POST /api/account/register`, `GET /api/account/verify`,
    `POST /api/account/password`, `POST /api/account/password/reset` (+ request-reset endpoint), validation, springdoc
    annotations, errors as RFC 9457 problem details. Mapper in the adapter; no domain object returned. `*Test` with MockMvc
    standalone and Mockito.
- [x] Task 19. Signing-key admin API and rotation job _(java-springboot)_ (api.web.keys admin controller, rotator, job, bootstrap runner, scheduling config; `SigningKeysRotatedEvent` in application.keys + `JwkCacheRefreshListener` in infrastructure/keys; unit tests added; validated in Group 5.)
  - [x] Task 19.1. `api.web.keys`: `GET /api/admin/keys`, `POST /api/admin/keys/rotate` (never exposes private material), springdoc.
  - [x] Task 19.2. `SigningKeyRotationJob` (`@Scheduled`, cron property, calls `RotateSigningKeysUseCase`), a startup bootstrap
    `ApplicationRunner`, `@EnableScheduling` configuration. Unit tests.
- [x] Task 20. Client admin API, seeding and dynamic registration _(java-springboot)_
  - [x] Task 20.1. `api.web.clients`: `/api/admin/clients` CRUD + `POST …/{clientId}/secret` rotation, DTOs without secrets (the secret is
    shown once on create / rotate), springdoc, unit tests. (auth-server/api/web `clients`: `ClientAdminController`, `ClientExceptionHandler`, `ClientRequest`, `ClientResponse`, `CreatedClientResponse`, `ClientSecretResponse`)
  - [x] Task 20.2. `ClientSeeder` (`ApplicationRunner`, uses `DefaultClientDefinitions`, secrets from
    `AUTHSERVER_BFF_CLIENT_SECRET`; warns and skips a confidential client without a secret) and `ClientSeedProperties`. (api/web `clients`; `authserver.clients.bff-secret=${AUTHSERVER_BFF_CLIENT_SECRET:}` in boot `application.yml`)
  - [x] Task 20.3. `DynamicClientRegistrationConfiguration`: a `ProtocolChainCustomizer` enabling the OIDC client registration endpoint
    when `authserver.oidc.client-registration.enabled=true`. Update `DevDataInitializer` to build `bff` from
    `DefaultClientDefinitions` (keeping its generated, logged secret). Update its tests. (api/web `DynamicClientRegistrationConfiguration`; persistence `DevDataInitializer` + test now use `ClientRegistrationRepository`)
- [x] Task 21. Token customisation and UserInfo _(java-springboot)_ — api/web `tokens` package; 11 unit tests added.
  - [x] Task 21.1. `api.web.tokens.JwtClaimsContributor` + `RolesTenantAudienceTokenCustomizer` (`OAuth2TokenCustomizer<JwtEncodingContext>`:
    `roles` from authorities, `tenant`, `aud` from the client's `audiences` setting). Tag `tokens-customizer`. — JwtClaimsContributor, RolesTenantAudienceTokenCustomizer.
  - [x] Task 21.2. `TokenSettingsFactory`/client token settings (TTLs, `reuseRefreshTokens(false)`, self-contained vs reference format).
    Tag `tokens-settings`. — no new factory: JdbcClientRegistrationRepository already builds TokenSettings from the registration; tag wrapped around that block.
  - [x] Task 21.3. `UserInfoMapper` (claims by granted scope: `sub`, `preferred_username`, `email`, `email_verified`, `roles`, `tenant`)
    registered through a `ProtocolChainCustomizer`. Tag `tokens-userinfo`. — UserInfoMapper + UserInfoConfiguration.
  - [x] Task 21.4. `ExpiredAuthorizationCleanupJob` (`@Scheduled`, calls `CleanExpiredAuthorizationsUseCase`). Unit tests for all. — done.
- [x] Task 22. Revoke authorizations on password change/reset wiring _(java-springboot)_
  - [x] Task 22.1. Provide the `UserAuthorizationRepository` bean wiring needed by `RevokeUserAuthorizationsUseCase`; verify no use
    case is left without an adapter (the context-load `*IT` in Group 7 catches missing beans). — `JdbcUserAuthorizationRepository` is a `@Repository` found by scanning; the audit of every domain port found one without an adapter (`TokenGenerator`), now `infrastructure.keys.SecureTokenGenerator` (SecureRandom, SHA-256); the Spring context starts in all `*IT`s.

  - Group 5 outcome: `./mvnw -o -B verify -DskipITs` green for the whole reactor (Checkstyle, PMD, CPD, SpotBugs, enforcer, ArchUnit, unit tests); unit-only line coverage 100% on every new class except `ApiSecurityConfig` (53%, thin filter-chain wiring covered by `ApiSecurityConfigIT`), `DevKeyEncryptionSecret` 87%, `RsaSigningKeyGenerator` 86%, `ReuseDetectingAuthorizationService` 93%. `./mvnw -o -B -pl auth-server/boot -am verify` (Docker): every `*IT` passes (AuthorizationCodePkceIT, JdbcServicesIT, SecurityConfigIT, SecurityIT, DevDataInitializerIT, ApiSecurityConfigIT, AuthServerApplicationIT, persistence ITs) except `OpenApiDriftIT`, which fails because `openapi/auth-server.json` is stale (expected, regenerated in Group 8). Fixes made while validating: `SpotBugs` EI_EXPOSE_REP in `ClientRequest` and NP in `RolesTenantAudienceTokenCustomizer`; missing `TokenGenerator` adapter; `ClientSeeder`/`SeedRegisteredClientsUseCase` now skip a confidential client without a secret (returns `SeedResult(created, skipped)`) so `spa-public` is still seeded; `ProtocolChainCustomizer` and `LoginChainCustomizer` no longer extend `Customizer<...>` because Spring Security 7.1 applies every such bean to every `HttpSecurity` (it turned the login and API chains into protocol chains, making `/account` answer 401); `test-support` gained `KeyEncryptionTestConfiguration` (runtime-generated `authserver.keys.encryption.*`, imported by `@PostgresIT`); `DevDataInitializerIT` now expects the `{argon2@SpringSecurity_v5_8}` prefix. The duplicated `settings.client.audiences` key (api/web vs persistence) was left as is: sharing it needs a constant visible to both adapters, which the hexagonal rules forbid except through `domain`.

### Group 6: Resource server API (Parallelizable: yes — separate files)

- [x] Task 23. Documents API _(java-springboot)_
  - [x] Task 23.1. `resource-server/api/web`: `documents.DocumentController` (`GET /api/documents` scope `documents.read`,
    `DELETE /api/documents/{id}` scope `documents.delete`), DTO record + mapper in the adapter, springdoc annotations,
    `@PreAuthorize` on the delete handler. Tags `resource-server-documents`, `resource-server-method-security`.
- [x] Task 24. Resource-server security _(java-springboot)_
  - [x] Task 24.1. `SecurityConfig`: `JwtAuthenticationConverter` (scopes via the default converter + `roles` claim → `ROLE_*`),
    `@EnableMethodSecurity`, RFC 6750 handlers (`insufficient_scope`, `invalid_token`), audience validator required (fail fast
    when empty). Tag `resource-server-converter`.
  - [x] Task 24.2. Opaque-token variant behind profile `opaque` (introspection URI + client credentials from environment).
  - [x] Task 24.3. `application.yml`: default audience `resource-server`; update `SecurityConfigIT`, `ResourceServerApplicationIT` and
    `ProtectedTestController` usages for the new audience.
- [x] Task 25. Resource-server OpenAPI _(java-springboot)_
  - [x] Task 25.1. Add springdoc to `resource-server`, an `api` group for `/api/**`, and `openapi/resource-server.json` plus a drift
    `*IT` mirroring `OpenApiDriftIT`.

  - Group 6 outcome: `api/web` gained `documents.{DocumentController,DocumentMapper,DocumentResponse}`, `OpenApiConfig` (group `api`, bearer scheme), `security.{BearerAuthorities,AudienceRolesOpaqueTokenIntrospector}` and a reworked `SecurityConfig` (`@EnableMethodSecurity`, scope rule for `GET /api/documents`, `@PreAuthorize` on delete, RFC 6750 handlers, audience required, `opaque` profile). Root pom manages `springdoc-openapi-starter-webmvc-api` (no Swagger UI). `application.yml` default audience `resource-server`, `application-opaque.yml` (env only, no defaults). `openapi/resource-server.json` + `OpenApiDriftIT` committed. Unit tests in api/web (22) and ITs in resource-server/boot (14) green, Checkstyle/PMD/CPD/SpotBugs/enforcer/ArchUnit green for resource-server; `SecurityConfig` unit coverage 53% (chain wiring, covered by `SecurityConfigIT`; the opaque chain has no IT until Task 31). auth-server `OpenApiDriftIT` still fails until Task 33 regenerates `openapi/auth-server.json` (not part of this group). Spring Security 7 adds `FACTOR_BEARER` to bearer authorities.

### Group 7: Integration tests (Parallelizable: yes — one `*IT` class per concern)

- [x] Task 26. `PasswordUpgradeIT` _(java-springboot)_: a `{bcrypt}` user is stored in `user_passwords`, logs in through the form, and the
  stored hash starts with `{argon2@SpringSecurity_v5_8}`; the compromised-password check is `@MockitoBean`.
- [x] Task 27. `AccountApiIT` _(java-springboot)_: register + verify, change password (authorizations revoked), reset with a single-use
  token (second use fails), unknown user answers like a known one.
- [x] Task 28. `KeyRotationIT` _(java-springboot)_: JWKS contents in each state; a token signed before rotation validates until the key is
  removed; admin endpoints need the `admin` scope.
- [x] Task 29. `TokenFlowIT` _(java-springboot)_: custom claims present; refresh rotation; reuse of a rotated refresh token revokes the
  authorization; revocation endpoint; introspection active / inactive; UserInfo content.
- [x] Task 30. `ClientAdminIT` _(java-springboot)_: seeding is idempotent and stores encoded secrets; CRUD and secret rotation through
  `/api/admin/clients`; dynamic registration when enabled.
- [x] Task 31. Resource-server `jwt()` slice tests _(java-springboot)_: audience, scopes, 401 / 403 `WWW-Authenticate` headers, delete denied
  without the scope, opaque profile with a mocked introspection endpoint.
- [x] Task 32. End-to-end real-token test _(java-springboot)_ in `e2e-tests`: start `auth-server` and `resource-server` jars (re-read
  `ManagedApp` / `SignInSmokeIT`), drive the authorization-code + PKCE flow with Playwright (intercepting the redirect), exchange the
  code, call `/api/documents` with the real token, expect 200, and a token with another audience to be rejected.
  - Group 7 outcome: `./mvnw -o -B clean verify -Dmaven.test.failure.ignore=true` green for the whole reactor (Checkstyle, PMD, CPD, SpotBugs, enforcer, ArchUnit, JaCoCo gate met); every `*IT` passes except `OpenApiDriftIT` in auth-server (stale `openapi/auth-server.json`, Task 33). Task 26: auth-server/boot `PasswordUpgradeIT` (3 tests: bcrypt upgraded to argon2 and still matches, wrong credential and current hash left untouched; compromised check `@MockitoBean`). Task 27: auth-server/boot `AccountApiIT` (10 tests: register + verify enables the account, taken e-mail answered the same, compromised password, change password revokes authorizations, reset token single use, unknown address answered like a known one). Production fix: `JdbcUserAccountRepository.markEmailVerified` now also enables the account (the port promised it; a verified user could never sign in); persistence IT updated. Task 28: auth-server/boot `KeyRotationIT` (4 tests: JWKS active+next without private part, retired key still validates an old token until removed, admin scope required). Rotation states are provoked by back-dating key rows. Task 29: auth-server/boot `TokenFlowIT` (9 tests: custom claims, client-credentials claims, refresh rotation, reuse revokes the authorization, revocation of access and refresh tokens, introspection, UserInfo, missing/invalid token). Production fixes in `RolesTenantAudienceTokenCustomizer`: `FACTOR_*` authorities no longer leak into `roles`, and the roles/audience claims are mutable lists, because the authorization store could not read back an immutable list (refresh, introspection and UserInfo failed); unit test added. Task 30: auth-server/boot `ClientAdminIT` (6 tests: idempotent seeding with encoded secrets, CRUD, secret rotation, admin scope required, dynamic registration with `client.create` token and encoded secret). Dynamic registration is exercised with `authserver.oidc.client-registration.enabled=true` and a runtime-generated bff secret. Task 31: resource-server/boot `OpaqueTokenSecurityIT` (6 tests, `opaque` profile with a local stub introspection endpoint that checks runtime-generated client credentials: active/inactive, other audience, missing scope, delete scope). The `jwt()` part (audience, scopes, 401/403 `WWW-Authenticate`, delete denied without the scope) was already covered by the 10 `SecurityConfigIT` tests. Task 32: e2e-tests `ResourceServerEndToEndIT` (3 tests: real token 200, token of another audience 401, no token 401) plus new `RunningAuthServer` helper shared with `SignInSmokeIT` (now also passes runtime-random key-encryption password/salt); `resource-server-boot` added to the e2e pom with the `resourceserver.jar` Failsafe property.

### Group 8: Contracts, docs and final verification (Parallelizable: no — each step depends on the previous result)

- [x] Task 33. Regenerate OpenAPI documents _(java-springboot)_ with `./mvnw -pl auth-server/boot -am verify -Dopenapi.update=true`
  (and the resource-server equivalent), review the diff for secrets and commit it.
  - openapi/auth-server.json regenerated, openapi/resource-server.json current; diff reviewed, no secret values (only schema field names); not committed.
- [x] Task 34. Run the full build via `iru-gate-runner` (`./mvnw -B clean verify`): Checkstyle, PMD/CPD, SpotBugs, JaCoCo 80 % / 70 %, enforcer, ArchUnit;
  fix findings without suppressions. Run `iru-check-security` (`detect-secrets`) and confirm no key or secret was added.
  - `./mvnw -B clean verify` green (all gates, unit + IT + e2e); aggregate line 99.17 %, branch 95.13 %; secret scan NEW_SECRETS: 0.
- [x] Task 35. Update `CLAUDE.md` (new modules, extension points, Flyway ranges used, dev key secret) and `docs/antora.yml` scans for every new module.
  - CLAUDE.md updated (layers, dev-only exceptions, Flyway ranges, key-encryption secret, OpenAPI drift ITs); docs/antora.yml already scans every module.
- [x] Task 36. Run `/iru-update-docs`; list every new tag (`password-policy`, `password-encoder`, `password-upgrade`, `account-schema`,
  `account-register`, `account-reset`, `keys-schema`, `keys-rotation`, `keys-encryption`, `keys-jwk-source`, `jwt-service`, `api-security`,
  `tokens-customizer`, `tokens-settings`, `tokens-userinfo`, `tokens-reuse-detection`, `clients-seed`, `clients-admin`,
  `resource-server-documents`, `resource-server-method-security`, `resource-server-converter`) in the PR description.
