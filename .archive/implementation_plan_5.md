# Implementation plan: Passkeys (WebAuthn) as passwordless primary method and second factor (issue #5)

## Task summary

Add **passkeys (WebAuthn / FIDO2)** to `auth-server` as a phishing-resistant **passwordless primary login** and as a
**second factor** after a password, with credential management (list, rename, delete) and virtual-authenticator e2e
tests. Plugs into the MFA framework of #4 and the login fragments of #3 through their extension points; no shared
file (`SecurityConfig`, `MfaPolicy`, `ApiSecurityConfig`) is edited.

Source: GitHub issue #5
Base branch: main
Flyway range: `V500`–`V599` only (`V500` WebAuthn schema: user entities and credentials, plus our own columns).

Choices made (challenge them in review):
- **Spring Security WebAuthn, not hand-rolled.** Use `http.webAuthn(...)` (`WebAuthnConfigurer`, present in
  `spring-security-config` 7.1.2) with `spring-security-webauthn` and webauthn4j. Neither jar is in the build yet:
  Task 1 adds them and verifies every class name and endpoint with `javap` before any code relies on them
  (`JdbcPublicKeyCredentialUserEntityRepository`, `JdbcUserCredentialRepository`, the official schema, the
  `FACTOR_WEBAUTHN` authority constant).
- **Two roles, two registered factors, one credential store.** `PasskeyFactor` registers `FACTOR_WEBAUTHN` (Spring's
  constant) as `PRIMARY_STRONG`: a passkey alone satisfies `MfaPolicy.isSatisfied`. A user who signed in with a password and
  then presents a passkey on `/login/second-factor` ends up with `FACTOR_PASSWORD` + `FACTOR_WEBAUTHN`, which already
  satisfies the policy (a `PRIMARY_STRONG` factor is sufficient), so no second authority is needed. `amr` lists
  `pwd`, `hwk` and `mfa` there. The `AuthenticationFactorRegistry` rule "one authority, one factor" is respected.
  Task 1 confirms that Spring Security 7.1 merges the existing factor authorities when the WebAuthn filter
  re-authenticates a session that already holds `FACTOR_PASSWORD`; if it does not, `PasskeyAuthenticationSuccess`
  (Task 7) re-adds them through `FactorGrantor`.
- **`amr` value `hwk`** (RFC 8176, proof of possession of a key held in hardware/platform authenticator). Synced
  passkeys are still reported as `hwk`; the backup-state flags are exposed on the account API instead.
- **Second-factor enrolment of passkeys**: a `SecondFactorEnrolmentQuery` bean (`HasConfirmedPasskeyUseCase`) makes a
  user with at least one registered passkey "a user who requires MFA", so the second-factor page is shown after a
  password login, and `StepUpGuard` applies to deleting the last passkey.
- **Own persistence columns** (`label`, `last_used_at`, plus Spring's `signature_count`, `backup_eligible`,
  `backup_state`) live in the `V500` migration. Spring's JDBC repositories store the credentials; the management
  API reads them through our own port `PasskeyRepository` (domain) implemented in `infrastructure/persistence`,
  never through a Spring type in `domain` or `application`.
- **Passkey-first sign-up** is attempted only if the Spring APIs allow registering a credential for a user that
  has no password. Otherwise the gap is recorded in `CLAUDE.md` and in the PR description (Task 12).
- **Relying party settings** (`authserver.passkeys.rp-name`, `rp-id`, `allowed-origins`) are bound once into a validated
  `@ConfigurationProperties` record, never read with `@Value`.

Open clarifications: none

## Acceptance criteria coverage

| # | Criterion | Covered by tasks |
|---|---|---|
| 1 | "All scope items are implemented and tested, and the e2e test is green in CI." | Task 2, Task 3, Task 4, Task 5, Task 6, Task 7, Task 8, Task 9, Task 10 |
| 2 | "`./mvnw verify` green, and the tags are listed in the PR." | Task 12, Task 13 |
| 3 | derived: `webAuthn()` is configured with `rpName`, `rpId`, `allowedOrigins`, and the four endpoints work | Task 1, Task 6 |
| 4 | derived: credentials are persisted through Flyway on the official schema in `V500`–`V599` | Task 3 |
| 5 | derived: passkeys can be registered from the account area with naming and `excludeCredentials` | Task 6, Task 7, Task 8 |
| 6 | derived: the login page offers conditional mediation autofill and a passkey button | Task 8 |
| 7 | derived: a passkey alone satisfies the strong-primary rule and `amr` reports it | Task 6, Task 10 |
| 8 | derived: `GET/PATCH/DELETE /api/account/passkeys` expose last-used, signature counter and backup flags | Task 4, Task 5, Task 7 |
| 9 | derived: a passkey works as the second factor after a password | Task 6, Task 8, Task 10 |
| 10 | derived: new Flyway range, tags and contract are checked by drift and architecture tests | Task 5, Task 9, Task 11, Task 12 |

## Current code state

- Placeholder packages already exist as `package-info.java` in every layer: `…domain.passkeys`,
  `…application.passkeys`, `…infrastructure.persistence.passkeys`, `…api.web.passkeys`
  (`auth-server/*/src/main/java/com/irurueta/authserver/authorization/`).
- Template to copy: `api/web/totp/` (`TotpFactor` registers an `AuthenticationFactor` bean;
  `TotpConfiguration` builds filters and returns a `LoginChainCustomizer`; `TotpChainCustomizer` permits paths and
  adds filters before `AuthorizationFilter`; `TotpSecondFactorFragment` is a `SecondFactorFragment`).
- Extension points: `api.web.login.LoginChainCustomizer`, `LoginMethodFragment` (rendered below the password form;
  `templates/password.html` already comments on `username webauthn`), `api.web.mfa.SecondFactorFragment`,
  `application.mfa.SecondFactorEnrolmentQuery`, `domain.mfa.AuthenticationFactor` / `FactorStrength.PRIMARY_STRONG`,
  `MfaPolicy.isSatisfied` (a `PRIMARY_STRONG` factor alone is enough), `FactorGrantor`, `MfaClaimsContributor`
  (writes `amr`/`acr`/`auth_time` from registered factors), `StepUpGuard` (RFC 9470 challenge for sensitive account
  operations), `SecurityEventAuthenticationEventPublisher`, `RecordSecurityEventUseCase`.
- Chains: `SecurityConfig.loginSecurityFilterChain` applies every `LoginChainCustomizer` before the catch-all rule.
- Contract: `apis/auth-server/rest-server/auth-server-api-v1.yaml` has `/api/account/totp`, `/recovery-codes` and
  `/trusted-devices/{id}`; `/webauthn/*` and `/login/webauthn` are framework-owned and exempt from the contract rule.
- Flyway: `auth-server/infrastructure/persistence/src/main/resources/db/migration` (`V400`–`V420` MFA is the latest).
- Tests: `boot` holds `SecurityConfigIT` and `OpenApiDriftIT`; `e2e-tests` drives the packaged jars with Playwright
  for Java (`BffEndToEndIT`, `SignInSmokeIT`, `RunningAuthServer`); CDP `WebAuthn.addVirtualAuthenticator` is the
  virtual authenticator.
- Archived precedents: `.archive/implementation_plan_4.md` (factor framework) and `implementation_plan_3.md` (login
  fragments).
- **Verified WebAuthn facts (Task 1, Spring Security 7.1.2, read from the real jars and sources):**
  - Dependency: `org.springframework.security:spring-security-webauthn` is managed by the Boot 4.1.2 BOM (7.1.2) and is
    declared in `auth-server/api/web/pom.xml` (so `boot` gets it transitively). It brings `com.webauthn4j:webauthn4j-core`
    `0.31.10.RELEASE` at compile scope (not BOM-managed, no pin needed). The `bannedDependencies` rule needed no change.
    **`infrastructure/persistence` does NOT have it yet**: `JdbcPublicKeyCredentialUserEntityRepository` and
    `JdbcUserCredentialRepository` live in the webauthn jar, so Task 3 must add `spring-security-webauthn` to
    `auth-server/infrastructure/persistence/pom.xml` (it already has spring-jdbc via `spring-boot-starter-jdbc`; check
    that module's banned list before adding).
  - `org.springframework.security.config.annotation.web.configurers.WebAuthnConfigurer<H>` (spring-security-config):
    `rpId(String)`, `rpName(String)`, `allowedOrigins(String...|Set<String>)`, `disableDefaultRegistrationPage(boolean)`,
    `messageConverter(HttpMessageConverter<Object>)`, `creationOptionsRepository(PublicKeyCredentialCreationOptionsRepository)`;
    entry point `http.webAuthn(...)`. `configure` needs a `UserDetailsService`, and uses a shared/bean
    `PublicKeyCredentialUserEntityRepository` and `UserCredentialRepository` (else in-memory `Map*`); it builds
    `WebAuthnAuthenticationFilter` (own `ProviderManager` with `WebAuthnAuthenticationProvider`, post-processed so
    `EnableMfaFiltersPostProcessor` sets `mfaEnabled`), `WebAuthnRegistrationFilter`,
    `PublicKeyCredentialCreationOptionsFilter`, `PublicKeyCredentialRequestOptionsFilter`, and a default registration page
    unless disabled. `init` registers a missing-authority entry point to `/login` for `FACTOR_WEBAUTHN`.
  - Packages (all in `org.springframework.security.web.webauthn.*` of spring-security-webauthn): `management`
    (`JdbcPublicKeyCredentialUserEntityRepository(JdbcOperations)`, `JdbcUserCredentialRepository(JdbcOperations)` with
    `setLobHandler`, `UserCredentialRepository` {`delete(Bytes)`, `save(CredentialRecord)`, `findByCredentialId(Bytes)`,
    `findByUserId(Bytes)`}, `PublicKeyCredentialUserEntityRepository` {`findById(Bytes)`, `findByUsername`, `save`,
    `delete(Bytes)`}, `Webauthn4JRelyingPartyOperations`, `CredentialRecordOwnerAuthorizationManager`), `api`
    (`CredentialRecord`, `ImmutableCredentialRecord`, `PublicKeyCredentialUserEntity`, `Bytes`), `authentication`
    (`WebAuthnAuthenticationFilter`, `WebAuthnAuthenticationProvider`, `WebAuthnAuthentication`), `registration`.
  - Framework endpoints (exempt from the contract rule): `POST /webauthn/authenticate/options`, `POST /login/webauthn`
    (JSON body, success is a JSON redirect via `HttpMessageConverterAuthenticationSuccessHandler`, failure 401),
    `POST /webauthn/register/options`, `POST /webauthn/register` (`WebAuthnRegistrationFilter`),
    `DELETE /webauthn/register/{id}`, `GET /webauthn/register` (default page). A client script ships as the classpath resource
    `org/springframework/security/spring-security-webauthn.js` in spring-security-web (its serving path was not verified).
  - Schema SQL (inside `spring-security-web-7.1.2.jar`, `org/springframework/security/`): `user-entities-schema.sql`
    (`user_entities(id varchar(1000) pk, name varchar(100) not null, display_name varchar(200))`) and
    `user-credentials-schema-postgres.sql` (`user_credentials(credential_id varchar(1000) pk, user_entity_user_id
    varchar(1000) not null, public_key bytea not null, signature_count bigint, uv_initialized boolean, backup_eligible
    boolean not null, authenticator_transports varchar(1000), public_key_credential_type varchar(100), backup_state
    boolean not null, attestation_object bytea, attestation_client_data_json bytea, created timestamp, last_used
    timestamp, label varchar(1000) not null)`). **The official table already has `label`, `created` and `last_used`**, so
    Task 3.1 must NOT add `label`/`last_used_at` columns; only an index on `user_entity_user_id` (and any FK to our
    users) is ours. `JdbcPublicKeyCredentialUserEntityRepository`/`JdbcUserCredentialRepository` columns must stay as
    above.
  - `FactorGrantedAuthority.WEBAUTHN_AUTHORITY = "FACTOR_WEBAUTHN"` (also `PASSWORD_AUTHORITY`, `OTT_AUTHORITY`,
    `X509_AUTHORITY`, ...). `WebAuthnAuthenticationProvider` returns a `WebAuthnAuthentication` (principal is the
    `PublicKeyCredentialUserEntity`, not our user type; `getName()` is the entity name) with the loaded user's authorities
    plus `FACTOR_WEBAUTHN`.
  - **Factor merge finding: existing factor authorities DO survive re-authentication, so Task 6.3 is not needed for
    merging.** `AbstractAuthenticationProcessingFilter.doFilter` (spring-security-web 7.1.2), when `mfaEnabled` (set on
    every such filter bean by `@EnableMultiFactorAuthentication` via `EnableMfaFiltersPostProcessor`, which the
    configurer's `postProcess` reaches), the current authentication is authenticated, the result declares `toBuilder()`
    (`WebAuthnAuthentication` does) and `current.getName().equals(result.getName())`, copies the current authorities
    (for example `FACTOR_PASSWORD`) onto the result. Caveat: the names must match, so the user-entity `name` must equal the
    username the password flow uses; with no prior login (anonymous name differs) nothing is merged, which is correct.
    This was verified by reading the sources, not run; Task 6/10 tests should still assert it end to end.
- **Passkey domain decision (Task 2):** `…domain.passkeys` did not exist in `domain` (only the other layers had placeholders); it is
  now filled. `Passkey.id` is a `String` (the unpadded base64url credential id, Spring's `user_credentials.credential_id`) and
  `Passkey.userId` is a `String` (the WebAuthn user handle, `user_credentials.user_entity_user_id`), NOT uuids: a credential id
  is authenticator-chosen bytes and cannot be a uuid. **Task 5 must declare the `{id}` path parameter and `Passkey.id` as a string
  (base64url, `maxLength` 1000, pattern `^[A-Za-z0-9_-]+$`), not uuid.** `PasskeyRepository` also has
  `findUserIdByUsername(String username)` (Optional; matched through `user_entities.name`) so a use case can go from the signed-in
  username to the user handle; `rename`/`delete` return `boolean`, use cases throw `PasskeyNotFoundException`.
- Stack: Java 21–25, Maven wrapper, Spring Boot 4.1 / Spring Security 7.1.2, hexagonal reactor with `bannedDependencies`
  in each module and `HexagonalArchitectureTest`.

## Implementation steps

### Group 1 — Dependencies (Parallelizable: yes, one task)

- [x] Task 1. Add and verify the WebAuthn dependencies _(java-springboot)_
  - [x] Task 1.1. Add `spring-security-webauthn` and webauthn4j (versions managed by the Spring Boot BOM if
        present, else pinned in the root `pom.xml` `dependencyManagement`) to `auth-server/api/web/pom.xml` and the
        `boot` runtime classpath; add them to that module's `bannedDependencies` allow-list only if the rule needs it
  - [x] Task 1.2. `javap` the real classes and write the verified names and endpoint paths into this plan's
        "Current code state" notes: `WebAuthnConfigurer`, `JdbcPublicKeyCredentialUserEntityRepository`,
        `JdbcUserCredentialRepository`, the schema SQL, `FactorGrantedAuthority.WEBAUTHN_AUTHORITY`, and whether
        existing factor authorities survive re-authentication
  - [x] Task 1.3. Run `./mvnw -B -pl auth-server/boot -am -DskipTests verify` to prove the build and the enforcer
        still pass (delegate to the `iru-gate-runner` agent)
  - Group 1 result: `auth-server/api/web/pom.xml` gets `spring-security-webauthn`; `-DskipTests verify` passed (enforcer,
    Checkstyle, PMD, SpotBugs, CPD); no tests apply, no new quality issues.

### Group 2 — Domain model and port (Parallelizable: yes, one task)

- [x] Task 2. Passkey domain model and ports in `…domain.passkeys` _(java-springboot)_
  - Result: `Passkey`, `PasskeyRepository`, `PasskeyNotFoundException`, `package-info` in `domain/passkeys`; `PasskeyTest`, `PasskeyNotFoundExceptionTest`; `-pl auth-server/domain -am verify` green (Checkstyle, PMD, CPD, SpotBugs, JaCoCo), passkeys classes fully covered.
  - [x] Task 2.1. `Passkey` record (`id`, `userId`, `label`, `createdAt`, `lastUsedAt`, `signatureCount`,
        `backupEligible`, `backedUp`); validate in the compact constructor with `Preconditions.requireText`
  - [x] Task 2.2. `PasskeyRepository` port (`findByUserId`, `findByIdAndUserId`, `rename`, `delete`,
        `countByUserId`) returning `Optional`/`List`, never `null`; `PasskeyNotFoundException`
  - [x] Task 2.3. `PasskeyTest` and exception tests (`constructor_whenLabelIsBlank_throwsIllegalArgumentException`)

### Group 3 — Persistence and use cases (Parallelizable: yes — Task 3 and Task 4 touch different modules and only the port from Group 2)

- [x] Task 3. Flyway `V500` and JDBC adapter in `…infrastructure.persistence.passkeys` _(java-springboot)_
  - [x] Task 3.1. `V500__webauthn.sql`: Spring's official WebAuthn tables (`user_entities`, `user_credentials`)
        with the license header and `-- tag::passkeys-schema[]` markers; the official table already has `label`,
        `created` and `last_used`, so only an index on `user_entity_user_id` is added
  - [x] Task 3.2. `JdbcPasskeyRepository` + `PasskeyRowMapper` (a `RowMapper<Passkey>` class), no own transaction
  - [x] Task 3.3. Bean wiring for Spring's JDBC repositories in a `@Configuration` of this module
  - [x] Task 3.4. `PasskeyRowMapperTest` (unit) and `JdbcPasskeyRepositoryIT` (`@PostgresIT`)
- [x] Task 4. Use cases in `…application.passkeys` _(java-springboot)_
  - [x] Task 4.1. `PasskeyProperties` (`authserver.passkeys.rp-name`, `rp-id`, `allowed-origins`, validated record)
  - [x] Task 4.2. `ListPasskeysUseCase`, `RenamePasskeyUseCase`, `DeletePasskeyUseCase` (`@Transactional`, using
        `@RequiredArgsConstructor`); delete records a security event through `RecordSecurityEventUseCase`
  - [x] Task 4.3. `HasConfirmedPasskeyUseCase` implemented as a `SecondFactorEnrolmentQuery` bean
  - [x] Task 4.4. One unit test class per production class (Mockito mocks, `@InjectMocks`)
- Group 3 result: `V500__webauthn.sql`; `JdbcPasskeyRepository`, `PasskeyRowMapper`, `WebAuthnJdbcConfiguration` (beans
  `publicKeyCredentialUserEntityRepository` and `userCredentialRepository`) in `infrastructure/persistence/passkeys`,
  `spring-security-webauthn` added to that module's pom; `PasskeyProperties`, `PasskeyConfiguration`, `ListPasskeysUseCase`
  `execute(String username)`, `RenamePasskeyUseCase` `execute(String username, String id, String label)` (label trimmed, max 100),
  `DeletePasskeyUseCase` `execute(UUID userId, String username, String id)` (audits `SECOND_FACTOR_REMOVED`, detail `passkey`),
  `HasConfirmedPasskeyUseCase` (`SecondFactorEnrolmentQuery`, resolves username through `UserAccountRepository`);
  `authserver.passkeys.*` defaults in boot `application.yml`. Unit tests per class + `JdbcPasskeyRepositoryIT`; unit and IT
  coverage 100% lines on the new classes; `-pl auth-server/boot -am verify` green (Checkstyle, PMD, CPD, SpotBugs, enforcer,
  ArchUnit, boot ITs), no new issues.

### Group 4 — Contract (Parallelizable: yes, one task)

- [x] Task 5. Add the passkey operations to `apis/auth-server/rest-server/auth-server-api-v1.yaml` _(java-springboot)_
  - [x] Task 5.1. `GET /api/account/passkeys`, `PATCH /api/account/passkeys/{id}`, `DELETE /api/account/passkeys/{id}`
        with every parameter, schema and property described and constrained (label length, `id` as uuid), the
        `Passkey` schema carrying `lastUsedAt`, `signatureCount`, `backupEligible` and `backedUp`, problem responses
        and the bearer scope as for `/api/account/totp`
  - [x] Task 5.2. Regenerate with `./mvnw -pl auth-server/api/web -am generate-sources`; commit nothing generated
  - Done: contract only; generate-sources and compile of auth-server/api/web succeed; no Java written (no tests/coverage/quality delta). OpenApiDriftIT expected to fail until Task 7.

### Group 5 — Web adapter (Parallelizable: yes — Tasks 6, 7 and 8 create disjoint files in `api/web`)

- [x] Task 6. WebAuthn wiring in `…api.web.passkeys` _(java-springboot)_
  - [x] Task 6.1. `PasskeyFactor` (`@Configuration`, `AuthenticationFactor` bean: id `passkey`, `amr` `hwk`,
        authority `FACTOR_WEBAUTHN`, `FactorStrength.PRIMARY_STRONG`)
  - [x] Task 6.2. `PasskeyConfiguration` returning a `LoginChainCustomizer` (`@Order` above TOTP) that calls
        `http.webAuthn(w -> w.rpName(...).rpId(...).allowedOrigins(...))`, permits `/webauthn/authenticate/options`
        and `/login/webauthn`, and keeps CSRF on; registration endpoints stay authenticated
  - [x] Task 6.3. `PasskeyAuthenticationSuccess` (only if Task 1.2 shows factors are not merged): keeps
        `FACTOR_PASSWORD` when a passkey completes the second-factor step, via `FactorGrantor`, and changes the
        session id — SKIPPED, not needed: the framework merges the factors (asserted in `PasskeyConfigurationIT`,
        amr `pwd`, `hwk`, `mfa`); the session id change is `SessionStrategyPostProcessor` (see Task 6.2)
  - [x] Task 6.4. `PasskeyLoginMethodFragment` (`LoginMethodFragment`) and `PasskeySecondFactorFragment`
        (`SecondFactorFragment`)
  - [x] Task 6.5. Unit tests per class and `PasskeyConfigurationIT` (slice with the customizer applied)
- [x] Task 7. Account API controller _(java-springboot)_
  - [x] Task 7.1. `PasskeyController` implementing the generated interface, calling the three use cases and
        `StepUpGuard` before delete when the user has a confirmed second factor
  - [x] Task 7.2. `PasskeyDtoMapper` (`@Component`) between `Passkey` and the generated DTO
  - [x] Task 7.3. Controller and mapper tests (MockMvc `andExpect` is fine), `PasskeyNotFoundException` mapped to a
        `404` problem body by a scoped `@RestControllerAdvice` or `ProblemJsonExceptionHandler`
- [x] Task 8. Templates and browser script _(java-springboot)_
  - [x] Task 8.1. `templates/passkeys.html` fragment: passkey button plus the `autocomplete="username webauthn"`
        input, conditional-mediation autofill script (CSP-safe: external file under `static/js/`, nonce or hash as
        `LoginContentSecurityPolicy` requires), tagged `passkeys-login`
  - [x] Task 8.2. Second-factor fragment (`templates/passkeys-second-factor.html`) with the "use a passkey" action
  - [x] Task 8.3. Registration helper in the account area (naming input, calls `/webauthn/register/options`,
        sends `excludeCredentials` as returned) and message keys in `messages*.properties`
  - [x] Task 8.4. Template rendering tests through `PageRenderer`, English locale set explicitly
- Group 5 result (web adapter, `api/web`, `infrastructure/persistence` one file, `apis/`): `PasskeyFactor`,
  `PasskeyConfiguration` (bean name `passkeyWebConfiguration`, the application one is `passkeyConfiguration`),
  `PasskeyChainCustomizer` (`@Order(2)`), `PasskeyRegistrationAuthorizationManager` + `PasskeyRegistrationFilter` (MFA guard of
  `/webauthn/register/**`, needed because Spring's creation-options filter answers before the chain's authorization filter),
  `AccountStatusUserDetailsService` (Spring's WebAuthn provider never checks the account status; a disabled account was able to
  sign in with a passkey), `SessionStrategyPostProcessor` (the configurer leaves the filter without a session strategy: no new session
  id), `PasskeyLoginMethodFragment`, `PasskeySecondFactorFragment`, `PasskeyController`, `PasskeyDtoMapper`,
  `PasskeyExceptionHandler`, `PasskeysPageController` + `PasskeyViewMapper` + `PasskeyView` (new account page `GET /account/passkeys`,
  contract `auth-server-pages-v1.yaml`, `OpenApiConfig` pages group), templates `passkeys.html`, `passkeys-second-factor.html`,
  `account-passkeys.html`, `static/js/passkeys.js`, `messages.properties`; `AuthorizationJsonMapperFactory` now adds
  `WebauthnJacksonModule` (without it every token request after a passkey sign-in failed: the stored principal could not be
  read back). ITs in `boot`: `PasskeyConfigurationIT` (mocked relying party), `PasskeyRegistrationIT` (real operations),
  `PasskeyPagesIT`; `PasswordAuthenticationIT.stripToken` also strips the new `data-csrf-token`. Unit tests per class, 100% line and
  branch on every new class (unit only); `-pl auth-server/boot -am verify` green (Checkstyle, PMD, CPD, SpotBugs, enforcer, ArchUnit,
  `OpenApiDriftIT`, 158 ITs), no new issues.

### Group 6 — Integration and end-to-end tests (Parallelizable: no — both e2e scenarios share the packaged auth-server and BFF fixtures and Playwright state)

- [x] Task 9. Integration tests in `auth-server/boot` _(java-springboot)_
  - [x] Task 9.1. Extend `OpenApiDriftIT` expectations only through the contract (no code change expected); confirm
        `HexagonalArchitectureTest` still passes
  - [x] Task 9.2. `PasskeyAccountIT` (`@PostgresIT`): list, rename, delete, step-up challenge on delete, ownership
- [x] Task 10. e2e test with a virtual authenticator in `e2e-tests` _(java-springboot)_
  - [x] Task 10.1. `PasskeyEndToEndIT`: CDP `WebAuthn.enable` + `addVirtualAuthenticator` (ctap2, internal,
        resident key, user verified), register a passkey from the account area, sign out, sign in through the BFF
        with the passkey, decode the access token and assert `amr` contains `hwk`
  - [x] Task 10.2. Second-factor scenario: password login, passkey on `/login/second-factor`, assert `pwd`, `hwk`
        and `mfa` in `amr`
  - [x] Task 10.3. Delegate the e2e run to the `iru-gate-runner` agent; they need Docker and a Chromium download
- Group 6 result: `PasskeyAccountIT` (9 tests: list, rename, delete, step-up, 404, ownership), `PasskeyEndToEndIT` (3 tests: button sign-in
  with the passkey alone, password then passkey on the second-factor page, passkey autofill), `RunningAuthServer` (passkey allowed origin
  from the random port, `createUserLikeDemo`). Production fix: `PasskeyExceptionHandler.handleInvalidParameter` (a malformed credential id
  was an unhandled `ConstraintViolationException`, now a 400 problem). `./mvnw -B -pl e2e-tests -am verify` green, 0 quality issues.

### Group 7 — Documentation and closing gates (Parallelizable: no — the final build must run after everything else)

- [x] Task 11. Update `CLAUDE.md`, the plan notes and the docs _(untagged)_
  - [x] Task 11.1. `CLAUDE.md`: add `passkeys` to the filled features, the `V500` range, the factor and fragment
        registrations, and the passkey-first sign-up gap if it exists
  - [x] Task 11.2. Run `/iru-update-docs` for the Antora pages that mention passkeys
- [x] Task 12. List the tags for the PR _(untagged)_
  - [x] Task 12.1. Collect every new `tag::passkeys-*[]` region (schema, login fragment, chain customizer,
        factor) and write them into the PR description for albertoirurueta/docs#345
- [x] Task 13. Full build gate _(java-springboot)_
  - [x] Task 13.1. `./mvnw -B clean verify` green: Checkstyle, PMD/CPD, SpotBugs, JaCoCo 80%/70%, Enforcer,
        ArchUnit, drift test, e2e (delegate to the `iru-gate-runner` agent and report only the summary)
  - [x] Task 13.2. Run `iru-check-security` and confirm no secret was added (test keys are generated inside tests)
- Group 7 result: Task 11.1 `CLAUDE.md` (passkeys filled, `V500`, `/account/passkeys` in both page lists, `PasskeyFactor`, `HasConfirmedPasskeyUseCase`, exempt `webAuthn` endpoints, registration filter and denied `DELETE /webauthn/register/**`, `AccountStatusUserDetailsService`, `WebauthnJacksonModule`, settings, the passkey-first sign-up gap and three known limitations) and the `lastUsedAt` description in `auth-server-api-v1.yaml` corrected (equal to createdAt until first use). Task 11.2 `iru-update-docs`: new `docs/modules/ROOT/pages/passkeys.adoc` + nav entry, rows in `data-model.adoc`, mention in `mfa-and-step-up.adoc`; Antora build clean. Task 12.1 ticked on the basis of a grep of the working tree (see `## Tags for the PR`), which is the correct basis since no PR exists. Task 13.1 `./mvnw -B clean verify` green: 1151 unit + 310 IT tests, 0 Checkstyle/PMD/CPD/SpotBugs findings, JaCoCo aggregate 99.11% line / 98.31% branch (gates 80/70), drift test and e2e included. Task 13.2 `iru-check-security`: 0 new, 0 unaudited, baseline still 40 entries, nothing labelled or hand-edited.

## Tags for the PR

For the PR description of albertoirurueta/docs#345 (verified by a grep of the working tree for `tag::passkeys-*[]`, each with its matching `end::` marker; no PR exists yet). Include syntax: `include::irurueta-auth-server::example$<path>[tag=<tag>]`.

| Tag | File |
|---|---|
| `passkeys-api-contract` | `apis/auth-server/rest-server/auth-server-api-v1.yaml` |
| `passkeys-authenticate` | `auth-server/api/web/src/main/resources/static/js/passkeys.js` |
| `passkeys-chain` | `auth-server/api/web/src/main/java/com/irurueta/authserver/authorization/api/web/passkeys/PasskeyChainCustomizer.java` |
| `passkeys-chain-customizer` | `auth-server/api/web/src/main/java/com/irurueta/authserver/authorization/api/web/passkeys/PasskeyConfiguration.java` |
| `passkeys-config` | `auth-server/boot/src/main/resources/application.yml` |
| `passkeys-factor` | `auth-server/api/web/src/main/java/com/irurueta/authserver/authorization/api/web/passkeys/PasskeyFactor.java` |
| `passkeys-jdbc-repositories` | `auth-server/infrastructure/persistence/src/main/java/com/irurueta/authserver/authorization/infrastructure/persistence/passkeys/WebAuthnJdbcConfiguration.java` |
| `passkeys-json-mapper` | `auth-server/infrastructure/persistence/src/main/java/com/irurueta/authserver/authorization/infrastructure/persistence/clients/AuthorizationJsonMapperFactory.java` |
| `passkeys-login` | `auth-server/api/web/src/main/resources/templates/passkeys.html` |
| `passkeys-page-api` | `apis/auth-server/web-pages/auth-server-pages-v1.yaml` |
| `passkeys-page-controller` | `auth-server/api/web/src/main/java/com/irurueta/authserver/authorization/api/web/passkeys/PasskeysPageController.java` |
| `passkeys-parameters` | `apis/auth-server/rest-server/auth-server-api-v1.yaml` |
| `passkeys-properties` | `auth-server/application/src/main/java/com/irurueta/authserver/authorization/application/passkeys/PasskeyProperties.java` |
| `passkeys-register` | `auth-server/api/web/src/main/resources/static/js/passkeys.js` |
| `passkeys-register-form` | `auth-server/api/web/src/main/resources/templates/account-passkeys.html` |
| `passkeys-schema` | `auth-server/infrastructure/persistence/src/main/resources/db/migration/V500__webauthn.sql` |
| `passkeys-schemas` | `apis/auth-server/rest-server/auth-server-api-v1.yaml` |
| `passkeys-second-factor` | `auth-server/api/web/src/main/resources/templates/passkeys-second-factor.html` |

18 tags in total. `docs/modules/ROOT/pages/passkeys.adoc` of this repository already includes 10 of them; not yet included anywhere: `passkeys-api-contract`, `passkeys-authenticate`, `passkeys-jdbc-repositories`, `passkeys-json-mapper`, `passkeys-page-api`, `passkeys-page-controller`, `passkeys-parameters`, `passkeys-register`.

## Security gate (resolved)

`iru-code` Step 7 stopped on one finding that the tracked-files-only scan could not see: `docs/modules/ROOT/pages/passkeys.adoc`,
line 12, `Secret Keyword`, hash prefix `f15e1855c2` (prose listing the `amr` values `pwd` and `hwk`). The user labelled it
a false positive on 2026-11-07. The file was staged, added to `.secrets.baseline` by `detect-secrets scan --baseline` and
marked `is_secret: false` (41 entries, 0 unaudited, 0 secrets). A `detect-secrets scan --all-files` over all 87 untracked
and modified files then reported only that entry and the existing `messages.properties` line 22, both triaged false
positives. Task 13 and Task 13.2 are closed.
