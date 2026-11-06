# Implementation plan: Multi-factor authentication and step-up (amr / acr), TOTP authenticator apps and recovery codes (issue #4)

## Task summary

Add the **MFA framework** every later login method plugs into (factor requirements, step-up, trusted devices, `amr` /
`acr` / `auth_time` reporting, audit and lockout) and the first second factor Spring does not provide: **TOTP
authenticator apps** (RFC 6238 / 4226) with **recovery codes**, in `auth-server`, plus the RFC 9470
`insufficient_user_authentication` challenge on `resource-server`'s sensitive endpoint.

Source: GitHub issue #4
Base branch: main
Flyway range: `V400`–`V499` only (`V400` security events and per-user enforcement, `V410` TOTP and recovery codes,
`V420` trusted devices).

Choices made (challenge them in review):
- **Spring Security 7.1 MFA API**: use `@EnableMultiFactorAuthentication`, `FactorGrantedAuthority` and
  `AuthorizationManagerFactories.multiFactor()` / `requireFactor(...)` (all present in 7.1.1). Task 1 verifies the exact
  signatures and authority constants with `javap` before any code relies on them.
- **Factors are an extension point, like `LoginChainCustomizer`.** A new `AuthenticationFactor` bean (id, `amr` value,
  `FactorGrantedAuthority` authority, strength `PRIMARY_STRONG` / `PRIMARY` / `SECOND`) registers a factor; the policy
  and the claims contributor read the registry, so #5 / #6 / #7 add factors without editing shared files. `CLAUDE.md`
  documents this (Task 17). The passkey factor (#5) is not implemented here: the policy treats any registered
  `PRIMARY_STRONG` factor as sufficient on its own, and none is registered yet.
- **Policy** (`MfaPolicy`, domain, pure): access to `/oauth2/authorize` requires a `PRIMARY_STRONG` factor, **or** a
  `PRIMARY` factor (password) plus any `SECOND` factor. MFA is *required* when the client's custom `ClientSettings`
  setting `settings.client.mfa.required` is true **or** the user's `users.mfa_required` is true; otherwise a
  password-only login stays valid (so existing flows and tests keep working). A user who has no enrolled second factor
  but is required to have one is sent to enrolment through the second-factor page.
- **Where MFA lives in the chains**: through `LoginChainCustomizer` (second-factor page, TOTP filter, trusted-device
  filter) and `ProtocolChainCustomizer` (step-up on `/oauth2/authorize`); `SecurityConfig` is **not** edited.
- **Step-up**: `acr_values` and `max_age` on `/oauth2/authorize` are honoured by a `ProtocolChainCustomizer` adding an
  `AuthorizationCodeRequestAuthenticationProvider` authentication validator (or converter, whichever Task 1 confirms is
  the supported extension point) that compares the session's reached `acr` / `auth_time` with the request and triggers
  re-authentication. `acr` values: `urn:irurueta:acr:pwd` (password only) and `urn:irurueta:acr:mfa` (two factors).
- **Claims**: a `JwtClaimsContributor` bean (`MfaClaimsContributor`) adds `amr`, `acr`, `auth_time` to access and ID
  tokens (the reference-token customizer picks it up through `IssuedTokenClaims`); it never touches #2's customizers.
  `amr` follows RFC 8176 (`pwd`, `otp`, `hwk`, `swk`, `sms`, `mfa`, `fed`); recovery-code logins report `otp` too.
- **TOTP**: implemented directly with `javax.crypto.Mac` (HMAC-SHA1, 30 s step, 6 digits, ±1 step window), replay
  protection through the last used time step stored per credential, 160-bit `SecureRandom` secret encrypted at rest with
  AES-GCM reusing the `authserver.keys.encryption.*` secret through a new `TotpSecretCipher` port (the existing
  `AesGcmKeyCipher` stays in `infrastructure/keys`; the adapter lives in `infrastructure/keys`, the only module allowed to
  hold that secret). The QR code is rendered server side with **ZXing** (`com.google.zxing:core` + `javase`) as a
  `data:image/png;base64` string; ZXing is added to the root `dependencyManagement` and to `auth-server/api/web` only.
- **Recovery codes**: 10 single-use codes, shown once, stored hashed with the `PasswordEncoder` bean, regenerable;
  the API returns "codes left" and the second-factor page warns when ≤ 3 remain.
- **Trusted devices**: a random 256-bit token in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie (`__Host-TRUSTED-DEVICE`),
  the row stores only the SHA-256 hash, user, UA summary and expiry (default 30 days); a trusted device skips the *second*
  factor, never the primary one. Revoked from `/api/account/trusted-devices/{id}`.
- **Audit & lockout**: an `AuthenticationEventPublisher` bean (Spring Security's) records login success/failure,
  second-factor success/failure, lockout and trusted-device events to `security_events`; after N (default 5, property
  `authserver.mfa.max-failed-attempts`) consecutive failed second-factor attempts the user's second factor is locked for
  `authserver.mfa.lockout` (default 15 minutes). Lockout uses a stored counter, not an in-memory map.
- **Resource server (RFC 9470)**: the sensitive endpoint is `DELETE /api/documents/{id}` (the only write operation of #2).
  A `BearerTokenAccessDeniedHandler` variant answers `401` with
  `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="urn:irurueta:acr:mfa", max_age="300"`
  when the token's `acr` is not the MFA one or its `auth_time` is older than `max_age`.
- **Contracts first**: the second-factor page goes into `apis/auth-server/web-pages/auth-server-pages-v1.yaml`; the TOTP,
  recovery-code and trusted-device endpoints into `apis/auth-server/rest-server/auth-server-api-v1.yaml`. No mapping
  annotation in hand-written code; DTOs come from the generator; mappers are `@Component` classes.
- **Per-client policy is edited through the admin API**: `mfaRequired` is added to the client admin contract and its
  mapper (touches the `clients` feature minimally; flagged for review).
- **Verified in Task 1** (`javap` on Spring Security 7.1.1 core/config and Authorization Server 7.1.2, the versions
  Spring Boot 4.1.2 resolves): `FactorGrantedAuthority` (`core.authority`, final) constants `PASSWORD_AUTHORITY`
  (`FACTOR_PASSWORD`), `OTT_AUTHORITY`, `WEBAUTHN_AUTHORITY`, `X509_AUTHORITY`, `SAML_RESPONSE_AUTHORITY`,
  `CAS_AUTHORITY`, `BEARER_AUTHORITY`, `AUTHORIZATION_CODE_AUTHORITY` (all `FACTOR_*`); there is no TOTP constant, so ours
  is a custom `FACTOR_TOTP` built with `withAuthority(String)` / `withFactor(String)` / `fromAuthority` / `fromFactor`, and
  an instance carries `getIssuedAt()`. `AuthorizationManagerFactories.multiFactor()` (`org.springframework.security.authorization`)
  returns `AdditionalRequiredFactorsBuilder<T>` with `when(Predicate<Authentication>)`, `withWhen(...)`,
  `requireFactors(String...)`, `requireFactors(Consumer<AllRequiredFactorsAuthorizationManager.Builder<T>>)`,
  `requireFactor(Consumer<RequiredFactor.Builder>)` and `build()` giving a `DefaultAuthorizationManagerFactory<T>`;
  `RequiredFactor.Builder` has `authority(String)`, `passwordAuthority()`, `ottAuthority()`, `webauthnAuthority()`,
  `x509Authority()` and `validDuration(Duration)` (freshness, usable for `max_age`). `@EnableMultiFactorAuthentication`
  (`config.annotation.authorization`) has `String[] authorities()` and `MultiFactorCondition[] when()`, RUNTIME retention.
  Step-up: `OAuth2AuthorizationEndpointConfigurer` has `authorizationRequestConverter(s)`, `authenticationProvider(s)`
  (`Consumer<List<AuthenticationProvider>>`), `authorizationResponseHandler`, `errorResponseHandler`, `consentPage`, but
  **no** `authenticationValidator`; that is a setter of `OAuth2AuthorizationCodeRequestAuthenticationProvider`
  (`setAuthenticationValidator(Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext>)`), reached through
  `authenticationProviders(list -> ...)`. The context exposes `getRegisteredClient()` and `getAuthorizationRequest()` (whose
  `getAdditionalParameters()` holds `acr_values` and `max_age`, which the standard converter does not interpret); the
  authentication is available through the context's `Authentication`. `OidcParameterNames` has `ACR`, `AMR`, `AUTH_TIME`.
  ZXing 3.5.4 (released 2025-11-11) is the latest and was added to the root `dependencyManagement` and to
  `auth-server/api/web` only; the module's enforcer rules still pass (`validate` green).

Open clarifications: none

## Acceptance criteria coverage

| # | Criterion | Covered by tasks |
|---|---|---|
| 1 | "All scope items are implemented and tested. `./mvnw verify` green, and the tags are listed in the PR." | Task 1 – Task 22 |
| 2 | derived: a password-only user whose client or account requires MFA is forced through a second factor before `/oauth2/authorize` completes | Task 11, Task 13, Task 19 |
| 3 | derived: TOTP codes match the RFC 6238 Appendix B vectors; the window and replay rules hold | Task 5, Task 8, Task 19 |
| 4 | derived: recovery codes are single use, shown once, hashed, regenerable | Task 6, Task 9, Task 16, Task 19 |
| 5 | derived: a trusted device skips the second factor and stops doing so after revocation | Task 10, Task 14, Task 16, Task 19 |
| 6 | derived: `amr`, `acr` and `auth_time` in ID and access tokens match the factors really used | Task 12, Task 19 |
| 7 | derived: `acr_values` / `max_age` force re-authentication; the resource server answers `insufficient_user_authentication` | Task 13, Task 18, Task 19 |
| 8 | derived: failed second-factor attempts are audited and lock out after N | Task 7, Task 9, Task 14, Task 19 |
| 9 | derived: contracts, drift test, ArchUnit and docs registration are updated | Task 15, Task 17, Task 20, Task 21 |

## Current code state

- **Placeholders**: `auth-server/api/web/.../api/web/mfa/package-info.java` and `.../totp/package-info.java` exist and are
  empty (`domain`, `application`, `infrastructure/persistence` have no `mfa` / `totp` packages yet).
- **Security chains**: `SecurityConfig` (`api/web`) defines `authorizationServerSecurityFilterChain` (`@Order(1)`,
  `ProtocolChainCustomizer` beans applied after `oidc`) and `loginSecurityFilterChain` (`@Order(2)`, `formLogin` plus
  `LoginChainCustomizer` beans before the catch-all). `api/web/login/LoginMethodFragment` + `templates/login.html` render
  login method fragments.
- **Claims**: `api/web/tokens/JwtClaimsContributor`, `IssuedTokenClaims`, `RolesTenantAudienceTokenCustomizer`,
  `ReferenceTokenClaimsCustomizer` exist; `MfaClaimsContributor` plugs in as a bean.
- **User**: `V101__users.sql` (`users`, `user_authorities`, `user_passwords`), `V200__account.sql` (email, tenant);
  `password/UserAccountUserDetailsService` + `UserDetailsMapper` build `UserDetails`. Flyway currently ends at `V240`.
- **Account API**: `api/web/account/AccountController` (+ `AccountExceptionHandler`, `AccountRateLimiter` on Bucket4j) and
  the contract `apis/auth-server/rest-server/auth-server-api-v1.yaml` (`/api/account/*`). `ApiSecurityConfig` is the
  stateless `/api/**` chain (bearer JWT, audience `auth-server`).
- **Key encryption**: `infrastructure/keys` (`AesGcmKeyCipher`, `KeyEncryptionProperties`, `KeyEncryptionConfiguration`,
  `DevKeyEncryptionSecret`).
- **Resource server**: `resource-server/api/web/security/SecurityConfig` (JWT and opaque chains, RFC 6750 handlers) and
  `documents/DocumentController` (`DELETE /api/documents/{id}`, `@PreAuthorize("hasAuthority('SCOPE_documents.delete')")`).
- **Tests**: `auth-server/boot/src/test/.../` holds `*IT` (`PasswordAuthenticationIT`, `AuthorizationCodePkceIT`,
  `OpenApiDriftIT`, `HexagonalArchitectureTest`, `AuthServerFixtures`).
- **Not present**: ZXing, `security_events`, `AuthenticationEventPublisher`, any `trusted_devices` table.
- **Spring Security 7.1.1** ships `FactorGrantedAuthority`, `AuthorizationManagerFactories`, `AuthorizationManagerFactory`,
  `@EnableMultiFactorAuthentication` (found in the local Maven cache).

## Implementation steps

### Group 1 — Foundations: API verification, dependency, domain models (Parallelizable: yes)

- [x] Task 1. Verify the Spring Security 7.1 MFA and Spring Authorization Server step-up APIs, and add ZXing _(java-springboot)_
  - Done: findings in *Choices made*; ZXing 3.5.4 in root `pom.xml` and `auth-server/api/web/pom.xml`; enforcer `validate` green.
  - [x] Task 1.1. With `javap` on `spring-security-core/config/7.1.1` and `spring-security-oauth2-authorization-server`,
    record the exact names/signatures/constants of `FactorGrantedAuthority` (`PASSWORD_AUTHORITY`, …),
    `AuthorizationManagerFactories.multiFactor()`, `requireFactor(...)`, `@EnableMultiFactorAuthentication`, and the
    authorization-endpoint extension point that can see `acr_values` / `max_age` (`authenticationValidator`, converter).
    Write the findings as a short "Verified in Task 1" bullet at the end of *Choices made* in this plan.
  - [x] Task 1.2. Add `com.google.zxing:core` and `com.google.zxing:javase` (latest release at least two weeks old) to the
    root `pom.xml` `dependencyManagement` and as dependencies of `auth-server/api/web/pom.xml`; confirm the enforcer
    `bannedDependencies` of that module still pass.
- [x] Task 2. Domain `mfa` package: model and ports _(java-springboot)_
  - Done: `auth-server/domain/.../domain/mfa` (+ tests); unit-only line coverage 100% on every class, no new Checkstyle/PMD/CPD/SpotBugs issues.
  - [x] Task 2.1. In `…domain.mfa`: `AuthenticationFactor` (record: `id`, `amrValue`, `authority`, `strength`),
    `FactorStrength` enum, `AuthenticationContextClass` constants (`pwd`, `mfa` URNs), `MfaPolicy` (pure: `isSatisfied(Set<AuthenticationFactor>)`,
    `isRequired(boolean clientRequires, boolean userRequires)`), `SecondFactorLockout` value, `TrustedDevice` record
    (`id`, `userId`, `hashedToken`, `userAgentSummary`, `expiresAt`, `createdAt`), `SecurityEvent` record (`type`, `userId`,
    `username`, `detail`, `occurredAt`), `SecurityEventType` enum. Validation through `domain.Preconditions`.
  - [x] Task 2.2. Ports: `TrustedDeviceRepository`, `SecurityEventRepository`, `SecondFactorAttemptRepository`
    (failed counter and lock-until per user), `UserMfaSettingsRepository` (`isRequired(userId)`, `setRequired`).
  - [x] Task 2.3. Unit tests: `MfaPolicyTest` (strong alone, password only, password + second, none), `TrustedDeviceTest`,
    `SecurityEventTest`; one test class per production class.
- [x] Task 3. Domain `totp` package: model, algorithm and ports _(java-springboot)_
  - Done: `auth-server/domain/.../domain/totp` (+ tests); unit-only line coverage 100% except `TotpAlgorithm` 91% (unreachable `GeneralSecurityException` catch); RFC 6238 Appendix B has six SHA-1 rows (not eight), all covered; no new quality issues. Added `SecureRandomSecretGenerator` (domain implementation of `SecretGenerator`) and `TotpAlgorithm.matchingStep` (returns the matched step to store).
  - [x] Task 3.1. In `…domain.totp`: `TotpCredential` (`userId`, `encryptedSecret`, `confirmed`, `lastUsedStep`, `createdAt`),
    `RecoveryCode` (`id`, `userId`, `hashedCode`, `usedAt`), `TotpAlgorithm` (pure, `javax.crypto.Mac` HMAC-SHA1:
    `generate(byte[] secret, long step)`, `matches(byte[] secret, String code, Instant now, long lastUsedStep)` with ±1
    window and replay rejection), `TotpUri` builder for `otpauth://totp/<issuer>:<account>?secret=<base32>&issuer=…&period=30&digits=6&algorithm=SHA1`,
    Base32 encoder (`Base32`), named constants for period/digits/window.
  - [x] Task 3.2. Ports: `TotpCredentialRepository`, `RecoveryCodeRepository`, `TotpSecretCipher` (`encrypt(byte[])` / `decrypt(byte[])`),
    `SecretGenerator` (160-bit `SecureRandom`; a `@Bean` per *Collaborators are beans*).
  - [x] Task 3.3. Unit tests: `TotpAlgorithmTest` (RFC 6238 Appendix B SHA-1 vectors at the eight listed times, 8-digit
    truncated to 6; window ±1 accepted, ±2 rejected; replay of the same step rejected), `TotpUriTest`, `Base32Test`,
    `RecoveryCodeTest`.

### Group 2 — Persistence adapters and migrations (Parallelizable: yes)

- [x] Task 4. `V400` security events and per-user MFA enforcement + JDBC adapters _(java-springboot)_ _(done: auth-server/infrastructure/persistence mfa package, V400; unit tests added; ITs unrun, group validation pending)_
  - [x] Task 4.1. `auth-server/infrastructure/persistence/src/main/resources/db/migration/V400__mfa_security_events.sql`:
    `ALTER TABLE users ADD COLUMN mfa_required boolean NOT NULL DEFAULT FALSE`; `security_events` (`id uuid`, `type`,
    `user_id uuid NULL`, `username`, `detail`, `occurred_at`, indexes on `(user_id, occurred_at)`); `second_factor_attempts`
    (`user_id` PK/FK, `failed_count`, `locked_until`). Tag `mfa-schema-events`. Apache header.
  - [x] Task 4.2. `…infrastructure.persistence.mfa`: `JdbcSecurityEventRepository`, `JdbcSecondFactorAttemptRepository`,
    `JdbcUserMfaSettingsRepository` with `RowMapper` classes; never return `null`; no transactions of their own.
  - [x] Task 4.3. `*IT` for each repository (`@PostgresIT`, JDBC slice), method names per convention.
- [x] Task 5. `V410` TOTP credentials and recovery codes + JDBC adapters _(java-springboot)_ — infrastructure/persistence (V410 migration, totp package); unit tests added; ITs written, not run; group validation pending.
  - [x] Task 5.1. `V410__totp_recovery_codes.sql`: `totp_credentials` (`user_id` PK/FK ON DELETE CASCADE, `encrypted_secret bytea`,
    `confirmed boolean`, `last_used_step bigint`, `created_at`), `recovery_codes` (`id`, `user_id` FK, `hashed_code`, `used_at`,
    `created_at`). Tag `totp-schema`.
  - [x] Task 5.2. `…infrastructure.persistence.totp`: `JdbcTotpCredentialRepository`, `JdbcRecoveryCodeRepository` with mappers.
  - [x] Task 5.3. `*IT` for both.
- [x] Task 6. `V420` trusted devices + JDBC adapter and `TotpSecretCipher` adapter _(java-springboot)_ (persistence + keys; unit tests added; group validation pending)
  - [x] Task 6.1. `V420__trusted_devices.sql`: `trusted_devices` (`id`, `user_id` FK, `hashed_token` unique, `user_agent`, `expires_at`,
    `created_at`). Tag `mfa-schema-trusted-devices`.
  - [x] Task 6.2. `JdbcTrustedDeviceRepository` + mapper, with an `*IT`.
  - [x] Task 6.3. `AesGcmTotpSecretCipher` in `infrastructure/keys` implementing the `TotpSecretCipher` port with the existing
    key-encryption secret (reuse `KeyEncryptionProperties`); unit test with runtime-generated secret (no committed key).

### Group 3 — Application use cases (Parallelizable: yes)

All use cases are `@Service`, `@RequiredArgsConstructor`, `@Transactional` (read-only when they only read); tests use
`@ExtendWith(MockitoExtension.class)` with `@InjectMocks`.

- [x] Task 7. `…application.mfa` use cases _(java-springboot)_
  - Done: auth-server/application `application.mfa` (5 + 5 use cases, `MfaConfiguration`, `TrustedDeviceTokens`, `CreatedTrustedDevice`) + tests; 100% line coverage (unit-only) except `TrustedDeviceTokens` 78% (unreachable `NoSuchAlgorithmException` catch); settings come from `@Value("${authserver.mfa.*}")` constructor values defined in `application` (same pattern as `SigningKeyRetention`), so `api/web`'s `MfaProperties` only binds/documents the same keys; domain `SecondFactorLockedException` added; no new Checkstyle/PMD/CPD/SpotBugs issues; boot ITs green.
  - [x] Task 7.1. `RecordSecurityEventUseCase`, `CheckSecondFactorLockoutUseCase`, `RegisterSecondFactorFailureUseCase` (counter,
    lock after `authserver.mfa.max-failed-attempts`), `ResetSecondFactorFailuresUseCase`, with `MfaProperties` (`@ConfigurationProperties`
    in `api/web`, passed in as values) and a `Clock` bean (reuse `application.time`).
  - [x] Task 7.2. `CreateTrustedDeviceUseCase` (returns the raw token once, stores SHA-256), `FindTrustedDeviceUseCase`,
    `ListTrustedDevicesUseCase`, `RevokeTrustedDeviceUseCase`, `CleanExpiredTrustedDevicesUseCase`.
  - [x] Task 7.3. A unit test class per use case.
- [x] Task 8. `…application.totp` use cases _(java-springboot)_
  - Done: `application.totp` Enroll/Confirm/Disable/Verify + tests; 100% line/branch (unit-only); domain exceptions `TotpAlreadyEnabledException`, `TotpNotEnrolledException`, `InvalidTotpCodeException` added with tests; no new quality issues.
  - [x] Task 8.1. `EnrollTotpUseCase` (generates secret, encrypts, stores unconfirmed, returns the `otpauth://` URI), `ConfirmTotpUseCase`
    (first code, replay step stored, then calls Task 9's generator through the port), `DisableTotpUseCase` (also deletes recovery codes),
    `VerifyTotpUseCase` (window, replay via `lastUsedStep`, lockout, events).
  - [x] Task 8.2. A unit test class per use case.
- [x] Task 9. Recovery code use cases _(java-springboot)_
  - Done: `application.totp` Generate/Verify/Count + `RecoveryCodes` component; hashing through the domain `PasswordHasher` port (the application module bans Spring Security, so the `PasswordEncoder` bean is reached through it); 100% line/branch (unit-only).
  - [x] Task 9.1. `GenerateRecoveryCodesUseCase` (10 codes, 10-character Crockford-style, hashed with the `PasswordEncoder` bean, replaces old),
    `VerifyRecoveryCodeUseCase` (single use, constant-time per code, lockout, events), `CountRecoveryCodesUseCase`.
  - [x] Task 9.2. A unit test class per use case.
- [x] Task 10. Collaborator beans _(java-springboot)_
  - Done: `application.mfa.MfaConfiguration` (`SecretGenerator`, `TotpAlgorithm`, `MfaPolicy`) + test, 100%.
  - [x] Task 10.1. `@Configuration` in `application` declaring `SecretGenerator`, `TotpAlgorithm`, `MfaPolicy` beans (no `new` inside use cases).

### Group 4 — Web: MFA framework, second-factor page, step-up, trusted devices (Parallelizable: no — Tasks 11–14 all contribute to the same security chains and the shared `templates/` / contract)

- [x] Task 11. Factor registry and policy wiring in `…api.web.mfa` _(java-springboot)_
  - Done: `auth-server/api/web/.../api/web/mfa` (MfaProperties, AuthenticationFactorRegistry, PasswordFactor, MfaAuthorizationManager, MfaLoginChainCustomizer, MfaProtocolChainCustomizer, SecondFactorRequiredEntryPoint/Exception, SecondFactorErrorResponseHandler, MfaConfiguration), `.../totp/TotpFactor`, plus `application.mfa.IsUserMfaRequiredUseCase`; unit tests added; group validated: ./mvnw clean verify green (unit + IT + Checkstyle/PMD/SpotBugs/JaCoCo gates; new classes 100% lines, aggregate 99.4% line).
  - [x] Task 11.1. `@EnableMultiFactorAuthentication` `MfaConfiguration`; `AuthenticationFactor` bean registry (`PasswordFactor` registered
    with `FactorGrantedAuthority.PASSWORD_AUTHORITY`, `TotpFactor` in `…api.web.totp` with a custom authority `FACTOR_TOTP`);
    `MfaAuthorizationManager` (uses `MfaPolicy` and the per-client / per-user flags) applied through a `LoginChainCustomizer`
    and a `ProtocolChainCustomizer` for `/oauth2/authorize`.
  - [x] Task 11.2. Second-factor flow: `SecondFactorRequiredEntryPoint` redirects to `/login/second-factor` keeping the saved
    authorize request (`HttpSessionRequestCache`); unit tests for the manager and entry point.
- [x] Task 12. Claims and event publishing _(java-springboot)_ — api/web `mfa`; unit tests added; group validated: ./mvnw clean verify green (unit + IT + Checkstyle/PMD/SpotBugs/JaCoCo gates; new classes 100% lines, aggregate 99.4% line).
  - [x] Task 12.1. `MfaClaimsContributor` (`@Order` after the built-in claims) adds `amr` (RFC 8176 values from the authentication's
    `FactorGrantedAuthority` list plus `mfa` when ≥ 2 factors), `acr` and `auth_time` (from the authentication timestamp); unit test and an
    `OAuth2TokenContext` slice test. (done: MfaClaimsContributor + MfaClaimsContributorTest; group validated: ./mvnw clean verify green (unit + IT + Checkstyle/PMD/SpotBugs/JaCoCo gates; new classes 100% lines, aggregate 99.4% line))
  - [x] Task 12.2. `SecurityEventAuthenticationEventPublisher` (`AuthenticationEventPublisher` bean) writing through `RecordSecurityEventUseCase`;
    unit test. (done: SecurityEventAuthenticationEventPublisher + test; group validated: ./mvnw clean verify green (unit + IT + Checkstyle/PMD/SpotBugs/JaCoCo gates; new classes 100% lines, aggregate 99.4% line))
- [x] Task 13. Step-up on `/oauth2/authorize` _(java-springboot)_
  - [x] Task 13.1. `StepUpProtocolChainCustomizer` (`ProtocolChainCustomizer`): reads `acr_values` and `max_age`, compares with the session's
    reached `acr` / `auth_time`, and forces re-authentication (clears the stale authentication for the request, redirects to login); unit tests
    for the validator. Done in auth-server/api/web (package `mfa`): StepUpProtocolChainCustomizer, StepUpAuthorizationRequestConverter,
    ReauthenticationEntryPoint, ReauthenticationRequiredException; unit tests added; group validated: ./mvnw clean verify green (unit + IT + Checkstyle/PMD/SpotBugs/JaCoCo gates; new classes 100% lines, aggregate 99.4% line).
- [x] Task 14. Second-factor page, TOTP provider and trusted-device filter _(java-springboot)_ — done in auth-server/api/web (packages `mfa`, `totp`), the pages contract, templates `second-factor.html` and `totp.html`, messages, `OpenApiConfig`, `spotbugs-exclude.xml`; unit tests added; group validated: ./mvnw clean verify green (unit + IT + Checkstyle/PMD/SpotBugs/JaCoCo gates; new classes 100% lines, aggregate 99.4% line).
  - [x] Task 14.1. `apis/auth-server/web-pages/auth-server-pages-v1.yaml`: add `GET /login/second-factor` (`text/html`); regenerate
    (`./mvnw -pl auth-server/api/web -am generate-sources`); `SecondFactorController` implements the generated interface and renders
    `templates/second-factor.html` with `PageRenderer`, which iterates a `SecondFactorFragment` bean list (extension point, same shape as
    `LoginMethodFragment`, with `templateName()`, `fragmentName()`, `order()`). Tag `mfa-second-factor-page`.
  - [x] Task 14.2. `TotpAuthenticationFilter` + `TotpAuthenticationProvider` (verifies through `VerifyTotpUseCase` and `VerifyRecoveryCodeUseCase`
    on `POST /login/second-factor/totp`, adds the TOTP `FactorGrantedAuthority` to the existing `Authentication`), `TotpSecondFactorFragment`
    (`templates/totp.html`, with the recovery-code link), `TotpChainCustomizer` (`LoginChainCustomizer` permitting the endpoint, CSRF kept on).
    POST handling is framework-owned (the filter) and therefore exempt from the contract rule, like `POST /login`. Add the endpoint to the exempt list in
    `HexagonalArchitectureTest` only if the rule requires it. Tag `totp-filter`.
  - [x] Task 14.3. `TrustedDeviceFilter` (reads `__Host-TRUSTED-DEVICE`, finds the device, grants the TOTP factor authority for the session), `TrustedDeviceCookieWriter`
    (`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`), the "remember this device" checkbox in `totp.html`. Unit tests for the filter, writer and fragment/controller.

### Group 5 — Web: account API (contract, controllers, mappers) (Parallelizable: no — every task edits the same contract and `AccountController`-adjacent files)

- [x] Task 15. Contract and generated interfaces _(java-springboot)_
  - [x] Task 15.1. `auth-server-api-v1.yaml`: add `POST /api/account/totp` (enrol → `otpauth` URI, `qrCode` data URI), `POST /api/account/totp/confirm`,
    `DELETE /api/account/totp`, `POST /api/account/recovery-codes` (returns the codes once and `remaining`), `GET /api/account/trusted-devices`,
    `DELETE /api/account/trusted-devices/{id}`; add `mfaRequired` to the client admin schema; every operation, parameter, schema and property
    described and constrained. Regenerate. Tag `totp-api-contract`.
    - Done: `apis/auth-server/rest-server/auth-server-api-v1.yaml` (tags Totp/Recovery codes/Trusted devices -> generated `TotpApi`, `RecoveryCodesApi`, `TrustedDevicesApi`; schemas `TotpEnrollmentResponse`, `ConfirmTotpRequest`, `RecoveryCodesResponse`, `TrustedDeviceResponse`; `mfaRequired` added to `ClientRequest`/`ClientResponse`); regenerated OK; group validation pending (`ClientDtoMapper` is adapted in Task 16.2).
- [x] Task 16. Controllers and mappers _(java-springboot)_
  - [x] Task 16.1. `TotpController`, `RecoveryCodeController`, `TrustedDeviceController` in `…api.web.totp` / `.mfa` implementing the generated interfaces,
    `TotpDtoMapper`, `TrustedDeviceDtoMapper` as `@Component`s, `QrCodeRenderer` (ZXing, PNG → `data:` URI), `MfaExceptionHandler` (`@RestControllerAdvice`, problem
    details). Tag `totp-enrollment`.
    - Done: api/web `totp/{TotpController,RecoveryCodeController,TotpDtoMapper,QrCodeRenderer}`, `mfa/{TrustedDeviceController,TrustedDeviceDtoMapper,MfaExceptionHandler,CurrentAccountResolver,CurrentAccount,TrustedDeviceNotFoundException}` (handler scoped to the generated `TotpApi`/`RecoveryCodesApi`/`TrustedDevicesApi`); unit tests for every class; group validation pending.
  - [x] Task 16.2. `mfaRequired` wiring in the `clients` admin mapper and use case (minimal edit, flagged); unit tests for every class.
    - Done (flagged, minimal edit): `ClientRegistration` (domain) gained the trailing `mfaRequired` component (all constructor call sites updated), `RegisteredClientMapper` stores it as `settings.client.mfa.required`, `ClientDtoMapper` maps it; use cases unchanged (they pass the registration through); tests updated/added; group validation pending.
  - [x] Task 16.3. MockMvc `*IT`s with `jwt()` for each endpoint (success, validation, unauthenticated, wrong user).
    - Done: `auth-server/boot/.../TotpApiIT` (jwt() per endpoint: success, validation, 401, other user's device 404); written, executed by the group integration stage; group validation pending.

### Group 6 — Documentation of the extension points (Parallelizable: yes)

- [x] Task 17. Update `CLAUDE.md` _(java-springboot)_ — CLAUDE.md only (documentation; no Java touched, so no build gates were run).
  - [x] Task 17.1. In *Extension points* add the factor registry (`AuthenticationFactor`, `SecondFactorFragment`, `StepUp…`), how #5 / #6 / #7 register a factor
    (a bean plus a `LoginChainCustomizer` plus a fragment plus an `AuthenticationProvider`) and the policy; update *Flyway ranges* (`V400`–`V420` used) and the
    feature-layout list (`mfa`, `totp` filled).

### Group 7 — Resource server: RFC 9470 (Parallelizable: yes)

- [x] Task 18. `insufficient_user_authentication` on `DELETE /api/documents/{id}` _(java-springboot)_
  - Group 7 done: unit tests (StepUp* classes, 100% line, 1 missed branch of 20+) and SecurityConfigIT / OpaqueTokenSecurityIT; no new Checkstyle/PMD/SpotBugs issues.
  - [x] Task 18.1. `resource-server/api/web/.../security/StepUpAuthorizationManager` (reads `acr` and `auth_time` from the JWT; the opaque variant from the introspection
    claims) applied to the delete rule, and `StepUpAccessDeniedHandler` answering `401` with `WWW-Authenticate: Bearer error="insufficient_user_authentication",
    acr_values="…", max_age="300"`, falling back to the RFC 6750 handler otherwise. Properties under `resourceserver.step-up.*` with defaults. Unit tests and an MVC `*IT`.
    Tag `resource-server-step-up`.
  - [x] Task 18.2. Update `apis/resource-server/rest-server/*-api-v1.yaml` with the `401` response and header description of the delete operation.

### Group 8 — Integration, drift and architecture tests (Parallelizable: no — they share `AuthServerFixtures` and the Postgres container)

- [x] Task 19. `*IT` in `auth-server/boot/src/test` _(java-springboot)_
  - Done: AbstractMfaFlow (shared base), MfaPasswordOnlyForcedIT, TotpLoginIT, RecoveryCodeIT, TrustedDeviceIT, StepUpIT, SecondFactorLockoutIT, AuthServerFixtures extended, resource-server StepUpDeletionIT + TestTokens (SecurityConfigIT now reuses it); e2e-tests/bff tests do not delete documents through a real login, so no adaptation was needed; `./mvnw -B clean verify` green, aggregate 99.3% line / 97.9% branch.
  - [x] Task 19.1. `MfaPasswordOnlyForcedIT` (client `mfa.required` forces the second-factor page; user `mfa_required`), `TotpLoginIT` (login, TOTP, tokens carry `amr`
    `[pwd, otp, mfa]`, `acr` mfa), `RecoveryCodeIT` (single use), `TrustedDeviceIT` (skip then revoke), `StepUpIT` (`acr_values` and `max_age` re-authenticate), `SecondFactorLockoutIT`.
  - [x] Task 19.2. Extend `AuthServerFixtures` with TOTP-enrolled users built at runtime (test secrets generated in the tests, nothing committed).
  - [x] Task 19.3. Resource-server end-to-end of `insufficient_user_authentication` in its own `*IT` (`resource-server/boot`).
- [x] Task 20. Contract drift and hexagonal rules _(java-springboot)_
  - [x] Task 20.1. Confirm `OpenApiDriftIT` passes with the new operations and the pages contract; add `/login/second-factor` to the `pages` springdoc group and the TOTP /
    recovery / trusted-device paths to the `api` group in `OpenApiConfig`.
  - [x] Task 20.2. Confirm `HexagonalArchitectureTest` (no mapping annotations in hand-written code, `@Transactional` on every use case, domain framework-free).
  - [x] Task 20.3. Run the full gates through the `iru-gate-runner` agent (`./mvnw -B clean verify`: tests, Checkstyle, PMD/CPD, SpotBugs, JaCoCo 80/70, enforcer).

### Group 9 — Docs and PR tags (Parallelizable: yes)

- [x] Task 21. Update the repository docs _(untagged)_
  - [x] Task 21.1. Run `/iru-update-docs` for the Antora module under `docs/modules/ROOT/pages` (MFA, TOTP, step-up pages) and refresh `README.md` status if it lists features.
- [x] Task 22. List the tags for the PR _(untagged)_
  - [x] Task 22.1. Collect every `tag::` added (`mfa-schema-events`, `totp-schema`, `mfa-schema-trusted-devices`, `mfa-second-factor-page`, `totp-filter`,
    `totp-api-contract`, `totp-enrollment`, `resource-server-step-up`, plus any added while implementing) for the PR description and the docs issue (albertoirurueta/docs#344).
    - Note (tags added in this branch, for the PR description and albertoirurueta/docs#344; each has a matching `end::`):
      - SQL (`auth-server/infrastructure/persistence/.../db/migration`): `mfa-schema-events` (V400), `totp-schema` (V410), `mfa-schema-trusted-devices` (V420).
      - Java auth-server (`api/web`): `mfa-second-factor-page` (SecondFactorController), `totp-filter` (TotpAuthenticationFilter and TotpAuthenticationProvider), `totp-enrollment` (TotpController).
      - Java auth-server (`infrastructure/persistence`): `mfa-record-failure` (JdbcSecondFactorAttemptRepository).
      - HTML templates: `mfa-second-factor-page-template` (second-factor.html), `totp-form` (totp.html).
      - OpenAPI: `mfa-second-factor-page-api` (auth-server-pages-v1.yaml), `totp-api-contract` and `totp-schemas` (auth-server-api-v1.yaml).
      - Java resource-server (`api/web/security`): `resource-server-step-up` (StepUpAuthorizationManager), `resource-server-step-up-handler` (StepUpAccessDeniedHandler), `resource-server-step-up-properties` (StepUpProperties), `resource-server-step-up-beans` (SecurityConfig).
    - Docs: new `docs/modules/ROOT/pages/mfa-and-step-up.adoc` (nav entry added), `data-model.adoc` (V400-V420), `resource-server.adoc` (step-up section); Antora build clean. README lists no per-feature status, unchanged. docs/antora.yml scans already cover every module and `apis`.
