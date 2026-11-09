# Implementation plan: tag regions for the docs pages of Authorization Server from Scratch part 2

## Task summary

Add the `tag::<name>[]` / `end::<name>[]` comment regions requested by issue #23 so that the docs follow-up
(`albertoirurueta/docs#344`, PR `#381`) can replace prose with
`include::irurueta-auth-server::example$<module-path>/src/...[tag=<name>]`. The change is comments only: no
behaviour, signature, dependency or contract semantics change. The one exception is the new `authserver.keys` block
in `application.yml`, whose values must equal the defaults already compiled into the code.

Source: GitHub issue #23
Base branch: main

Choices made on the user's behalf:
- **`keys-config`**: no `authserver.keys` block exists in `auth-server/boot/src/main/resources/application.yml`; the code
  reads `authserver.keys.clock-skew` (`PT60S`), `jwks-cache-ttl` (`PT30S`), `retention` (`PT2H`), `rotation-interval`
  (`P30D`) and `rotation.cron` (`0 0 * * * *`) through `@Value` defaults, plus `encryption.password` / `.salt`, which are
  secrets with no default. The plan adds a block with exactly those documented defaults (issue option 1) and
  mentions the two secrets only as a comment pointing to the environment variables, never as values.
- **Shared tag names across files**: `clients-seeding` goes on `ClientSeeder`, `SeedRegisteredClientsUseCase` and
  `ClientSeedProperties`, because Antora includes one file at a time; the same name in several files is valid.
- **Tests**: one representative test per `*-it` tag, chosen as named in the plan; the two token-reuse tags use the
  tests named after the replay behaviour.
- **Existing regions are never renamed or removed.** New regions that overlap existing ones (`api-security`,
  `resource-server-security`) are placed outside them or fully nested inside them, whichever keeps both includable;
  Asciidoctor tag regions may nest but must not interleave.

Open clarifications: none

## Acceptance criteria coverage

| # | Criterion | Covered by tasks |
|---|---|---|
| 1 | "Each file above has the listed regions, using `tag::name[]` / `end::name[]` comments in the file's own comment syntax, following the `<feature>-<what>` naming in `CLAUDE.md`." | Task 1, Task 2, Task 3, Task 4, Task 5 |
| 2 | "No region contains a credential, secret or key value." | Task 1.2, Task 6.1 |
| 3 | "The `clients-api` region wraps only the `/api/admin/clients` paths." | Task 1.3 |
| 4 | "The tag names are listed in the PR description, so the docs follow-up can replace the prose in the pages above with includes." | Task 8.2 |
| 5 | "`./mvnw verify` stays green." | Task 7 |

## Current code state

Explored in `iru-explore` (none of the requested tags exists on `main`, checked by search). All paths below are
relative to the repository root. `AS` = `auth-server`, `ASW` = `auth-server/api/web/src/main/java/com/irurueta/authserver/authorization/api/web`,
`ASA` = `auth-server/application/src/main/java/com/irurueta/authserver/authorization/application`,
`ASK` = `auth-server/infrastructure/keys/src/main/java/com/irurueta/authserver/authorization/infrastructure/keys`,
`ASD` = `auth-server/domain/src/main/java/com/irurueta/authserver/authorization/domain`,
`ASIT` = `auth-server/boot/src/test/java/com/irurueta/authserver/authorization`.

- Contract `apis/auth-server/rest-server/auth-server-api-v1.yaml`: `# tag::clients-api[]` is at line 532 (above
  `identities-api-contract`) and its `# end::clients-api[]` at line 852; `/api/admin/clients` begins at line 693,
  right after `# end::certificates-api-contract[]`. `clients-schemas` (1269–1516) already exists.
- `AS/boot/src/main/resources/application.yml`: `authserver.account.rate-limit` block at lines 96–103 (no tag);
  no `authserver.keys` block (see choices). Existing tags in that file use `  # tag::x[]` at the indentation of
  the block they wrap (for example `ott-rate-limit-config`).
- `ASW/ApiSecurityConfig.java`: `api-security` region begins at line 82; `ADMIN_PATTERN`, `ADMIN_SCOPE_AUTHORITY` and
  the audience validator (`apiJwtDecoder`) are the targets of `api-admin-scope`.
- `resource-server/api/web/.../security/SecurityConfig.java`: `resource-server-security` (63), `-bound-tokens` (85),
  `-step-up-beans` (120), `-converter` (166); `authorize(...)` is a private static method at line 193.
- `resource-server/boot/.../application.yml`: `spring.security.oauth2.resourceserver` at line 20.
- `bff/boot/.../application.yml`: session at line 26 and `spring.security.oauth2.client.registration` at line 33.
- Test methods available: `TokenFlowIT.refresh_whenRotatedTokenIsReused_revokesTheAuthorization`,
  `ReuseDetectingAuthorizationServiceIT.findByToken_whenRotatedTokenIsReplayed_revokesTheAuthorization`;
  `LoginPageIT`, `ConsentPageIT`, `LogoutIT` and `KeyRotationIT` need a representative test chosen when read.
- Every other file in the issue exists at the path named in the issue (verified by `find`).
- Style: Java files use `// tag::x[]`; YAML uses `# tag::x[]`; Checkstyle, PMD, SpotBugs and Spotless-style rules
  still apply to the surrounding code, so a tag comment must sit on its own line at the surrounding indentation and
  never between an annotation and its element or between Javadoc and its element.

## Implementation steps

Stack key for every task: `java-springboot` (hexagonal Spring Boot reactor, Maven).

### Group 1 — auth-server main sources, YAML and contract (Parallelizable: yes — each task edits different files)

- [x] Task 1. Add the passwords, keys, tokens, clients, login and consent regions in `auth-server` _(java-springboot)_
  - [x] Task 1.1. `AS/boot/.../application.yml`: wrap the `authserver.account.rate-limit` block in
    `# tag::account-rate-limit-config[]` / `# end::account-rate-limit-config[]`.
  - [x] Task 1.2. Same file: add an `authserver.keys` block with `clock-skew: PT60S`, `jwks-cache-ttl: PT30S`,
    `retention: PT2H`, `rotation-interval: P30D`, `rotation.cron: "0 0 * * * *"`, each with a one-line comment, and a
    comment saying `encryption.password` and `encryption.salt` come only from `AUTHSERVER_KEYS_ENCRYPTION_PASSWORD` /
    `AUTHSERVER_KEYS_ENCRYPTION_SALT` (no value written); wrap it in `keys-config`. Values must equal the `@Value`
    defaults so behaviour is unchanged.
  - [x] Task 1.3. `apis/auth-server/rest-server/auth-server-api-v1.yaml`: move `# tag::clients-api[]` from line 532 to
    just above `  /api/admin/clients:` (line 693); leave `# end::clients-api[]` where it is (after the last admin client
    path). Check no other tag now straddles it and that `OpenApiDriftIT` is unaffected (comments only).
  - [x] Task 1.4. `ASA/account/ChangePasswordUseCase.java` → `account-change-password` (the use case body, not its
    imports/header); `ASW/account/AccountController.java` → `account-controller`.
  - [x] Task 1.5. `ASW/keys/SigningKeyRotationJob.java` → `keys-rotation-job`; `ASW/keys/SigningKeyBootstrapRunner.java` →
    `keys-bootstrap`; `ASW/keys/SigningKeyAdminController.java` → `keys-admin-controller`;
    `ASK/JwkCacheRefreshListener.java` → `keys-cache-refresh`;
    `auth-server/infrastructure/persistence/.../keys/RegisteredClientTokenLifetimes.java` → `keys-token-lifetimes`.
  - [x] Task 1.6. `ASW/tokens/ExpiredAuthorizationCleanupJob.java` → `tokens-cleanup-job`;
    `ASA/tokens/CleanExpiredAuthorizationsUseCase.java` → `tokens-cleanup`.
  - [x] Task 1.7. Clients: `ASW/clients/ClientSeeder.java`, `ASA/clients/SeedRegisteredClientsUseCase.java` and
    `ASW/clients/ClientSeedProperties.java` → `clients-seeding` (same name in each file). In `ASW/ApiSecurityConfig.java`
    add `api-admin-scope` around `ADMIN_PATTERN`/`ADMIN_SCOPE_AUTHORITY` and the audience validation of `apiJwtDecoder`;
    keep `api-security` intact and do not interleave (put the new regions outside it, or split `api-admin-scope` into
    two includable regions only if the code is non-contiguous: in that case use two `tag::api-admin-scope[]` pairs,
    which Asciidoctor concatenates).
  - [x] Task 1.8. `ASW/consent/ConsentProtocolCustomizer.java` → `consent-protocol-customizer`;
    `ASW/login/LoginMethodFragment.java` (the interface and `reference()`) → `login-method-fragment`;
    `ASW/consent/ConsentPageModelMapper.java` → `consent-model-mapper`.
  - [x] Task 1.9. TOTP: `ASD/totp/TotpAlgorithm.java` (RFC 6238/4226 computation and the window check) →
    `totp-algorithm`; `ASK/AesGcmTotpSecretCipher.java` → `totp-secret-cipher`; `ASA/totp/VerifyTotpUseCase.java` →
    `totp-verify`; `ASA/totp/VerifyRecoveryCodeUseCase.java` → `totp-verify-recovery-code`; optional ones from the
    issue: `EnrollTotpUseCase` → `totp-enroll-use-case`, `ConfirmTotpUseCase` → `totp-confirm-use-case`,
    `ASD/totp/TotpUri.java` → `totp-uri`.

### Group 2 — auth-server test sources (Parallelizable: yes — different test files)

- [x] Task 2. Add the test regions _(java-springboot)_ — comment-only regions added; test-compile and Checkstyle green.
  - [x] Task 2.1. `ASIT/KeyRotationIT.java` → `keys-rotation-it` around the rotation test (read the class; pick the
    one that rotates and checks old and new keys).
  - [x] Task 2.2. `ASIT/TokenFlowIT.java` → `tokens-reuse-it` around
    `refresh_whenRotatedTokenIsReused_revokesTheAuthorization`.
  - [x] Task 2.3. `auth-server/infrastructure/persistence/src/test/.../tokens/ReuseDetectingAuthorizationServiceIT.java`
    → `tokens-reuse-detection-it` around `findByToken_whenRotatedTokenIsReplayed_revokesTheAuthorization`.
  - [x] Task 2.4. `ASIT/LoginPageIT.java` → `login-page-it`, `ASIT/ConsentPageIT.java` → `consent-page-it`,
    `ASIT/LogoutIT.java` → `logout-it`: one representative test each (include its `@Test` annotation inside the
    region so the include reads as a test).

### Group 3 — resource-server and BFF (Parallelizable: yes — different modules and files)

- [x] Task 3. Resource server regions _(java-springboot)_
  - [x] Task 3.1. `resource-server/boot/src/main/resources/application.yml`: wrap
    `spring.security.oauth2.resourceserver` → `resource-server-config`.
  - [x] Task 3.2. `resource-server/api/web/.../security/SecurityConfig.java`: wrap the `authorize(...)` rules in
    `resource-server-authorize` (the method's `http.authorizeHttpRequests(...)` statement), without touching or
    interleaving the existing `resource-server-*` regions.
- [x] Task 4. BFF regions _(java-springboot)_
  - [x] Task 4.1. `bff/api/web/.../login/ReturnToValidator.java` → `bff-return-to-validator`;
    `bff/api/web/.../security/CsrfCookieFilter.java` → `bff-csrf-cookie-filter`;
    `bff/api/web/.../login/StepUpAuthorizationRequestResolver.java` → `bff-step-up-resolver`.
  - [x] Task 4.2. `bff/boot/src/main/resources/application.yml`: wrap the OAuth2 client registration and the session
    settings → `bff-config` (one region if contiguous, else two regions with the same name; no client secret value
    inside: it must be an environment placeholder already, verify).

### Group 4 — verification and PR notes (Parallelizable: no — runs after all regions exist)

- [x] Task 5. Check every tag pairs and is unique where required _(untagged)_
  - [x] Task 5.1. Script a check (`grep -rn "tag::\|end::"` over the changed files) that each requested name appears
    with a matching `end::`, no region is interleaved with another in the same file, and the requested names from the
    issue all exist at least once.
- [x] Task 6. Secret and docs-site check _(untagged)_
  - [x] Task 6.1. Run the `iru-check-security` skill over the changed files (delegate to the `iru-gate-runner` agent);
    confirm no region contains a credential, secret or key value.
  - [x] Task 6.2. Confirm the docs site still builds (`cd docs && npm ci && npx antora antora-playbook.yml`); the
    tags are not yet used by pages, so this only guards `docs/antora.yml` scans.
- [x] Task 7. Full build gate _(untagged)_
  - [x] Task 7.1. Delegate `./mvnw -B clean verify` to the `iru-gate-runner` agent (needs Docker); it must be green
    (Checkstyle, PMD/CPD, SpotBugs, JaCoCo, enforcer, ArchUnit, `OpenApiDriftIT`).
- [x] Task 8. PR description notes _(untagged)_
  - [x] Task 8.1. Keep a list of every tag added, grouped by docs page, in the order of the issue, plus the note that
    `keys-config` is a new block with the compiled defaults and no secret values.
  - [x] Task 8.2. Put that list in the PR description (the `iru-pr-description` step) so the docs follow-up can replace
    the prose with includes.
  - [x] Task 8.3. Mention that `CLAUDE.md`'s tag-comment convention is unchanged and no tag was renamed or removed.

## PR description notes (tag list)

_Text to paste into the PR description (the PR is opened in a later step; none was created or edited here)._

Comment-only `tag::<name>[]` / `end::<name>[]` regions for issue #23, grouped by docs page, in the order of the issue,
so the docs follow-up (albertoirurueta/docs#344, PR #381) can replace prose with `include::...[tag=...]`:

- **Passwords and accounts** (`password-storage.adoc`): `account-rate-limit-config`, `keys-config` (both in
  `auth-server/boot/.../application.yml`), `account-change-password`, `account-controller`.
- **Signing keys** (`signing-keys-jws-and-jwt.adoc`): `keys-rotation-job`, `keys-bootstrap`, `keys-admin-controller`,
  `keys-cache-refresh`, `keys-token-lifetimes`, `keys-rotation-it`.
- **Tokens** (`access-refresh-and-id-tokens.adoc`): `tokens-cleanup-job`, `tokens-cleanup`, `tokens-reuse-it`,
  `tokens-reuse-detection-it`.
- **Registered clients** (`registered-clients.adoc`): `clients-api` (start tag moved, see below), `clients-seeding`
  (in `ClientSeeder`, `SeedRegisteredClientsUseCase`, `ClientSeedProperties`), `api-admin-scope` (two regions of
  `ApiSecurityConfig`, outside `api-security`).
- **Resource server** (`resource-server.adoc`): `resource-server-config`, `resource-server-authorize`.
- **Login, consent and logout pages** (`login-and-consent-pages.adoc`): `consent-protocol-customizer`,
  `login-method-fragment`, `consent-model-mapper`, `login-page-it`, `consent-page-it`, `logout-it`.
- **BFF** (`backend-for-frontend.adoc`): `bff-return-to-validator`, `bff-csrf-cookie-filter`, `bff-step-up-resolver`,
  `bff-config`.
- **TOTP and recovery codes** (`totp-and-recovery-codes.adoc`): `totp-algorithm`, `totp-secret-cipher`, `totp-verify`,
  `totp-verify-recovery-code`, `totp-enroll-use-case`, `totp-confirm-use-case`, `totp-uri`.

`keys-config` is a new `authserver.keys` block with only the compiled defaults (clock-skew `PT60S`, jwks-cache-ttl
`PT30S`, retention `PT2H`, rotation-interval `P30D`, rotation.cron `0 0 * * * *`) and no secret values; the encryption
password and salt are only mentioned as coming from `AUTHSERVER_KEYS_ENCRYPTION_PASSWORD` /
`AUTHSERVER_KEYS_ENCRYPTION_SALT`.

`CLAUDE.md`'s tag-comment convention is unchanged and no tag was renamed or removed: `git diff` shows the only removed
tag line is `# tag::clients-api[]`, which was moved (not renamed) from above the account paths to just above
`/api/admin/clients` so the region wraps only the admin client paths (Task 1.3).
