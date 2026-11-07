# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. Follow these
rules over any general-purpose default. Where a rule below and a generated scaffold disagree, this file wins.

## What this is

An **example** OAuth 2.1 / OpenID Connect authorization server built from scratch with Spring Boot 4.1 and Spring
Security 7.1 (Spring Authorization Server), plus the applications that use it. It backs the step-by-step guide
*Building an Authorization Server from Scratch* in the docs site (repository `albertoirurueta/docs`, under
`modules/ROOT/pages/backend/springboot/authorization-server-from-scratch/`), which includes code from this repository
with tagged regions. The applications are never deployed: CI only builds, analyses and tests them, and publishes the
documentation (Antora site plus Maven site reports) to GitHub Pages.

## Commands

Requires JDK 21–25 (the build enforces `[21,26)`; SpotBugs cannot parse JDK 26+ class files) and Docker for
Testcontainers.

```bash
./mvnw -B clean verify                 # unit (*Test) + integration (*IT) tests and every build gate (must be green)
./mvnw test                            # fast unit-test run only, no Spring context starts
./mvnw -pl auth-server/api/web -am test -Dtest=LoginControllerTest   # one test class in one module
./mvnw -pl auth-server/boot -am spring-boot:run -Dspring-boot.run.profiles=dev   # run one application
./mvnw install && ./mvnw site site:stage -DskipTests   # browsable reports, staged as published under /mvn-site
cd docs && npm ci && npx antora antora-playbook.yml            # build this repository's Antora docs
```

Ports: auth-server 9000, bff 8080, resource-server 8081.

## Architecture

Hexagonal, one Maven sub-reactor per application, enforced twice: by `maven-enforcer-plugin` `bannedDependencies` in
each module's pom (jar granularity) and by a `HexagonalArchitectureTest` (ArchUnit) in each application's `boot`
module (package granularity). Never weaken either to make code fit; move the code instead.

```
<app>/                          aggregator pom (packaging pom), artifactId <app>-parent
  domain/                       <app>-domain
  application/                  <app>-application
  infrastructure/<adapter>/     <app>-infrastructure-<adapter>   (driven adapters: persistence, keys, ...)
  api/<adapter>/                <app>-api-<adapter>              (driving adapters: web, ...)
  boot/                         <app>-boot                       (composition root, the only runnable artifact)
```

| Module | May depend on | Must not contain |
|---|---|---|
| `domain` | nothing but the JDK (and Lombok, compile-only) | Spring, Jackson, JPA/JDBC, Spring Security types: the only framework-free module |
| `application` | `domain`, Spring | Spring Security types; use cases are `@Service` beans found by component scanning |
| `infrastructure/*` | `domain`, `application` | a sibling adapter, any `api/*` module |
| `api/*` | `domain`, `application` | any `infrastructure/*` module; a mapping annotation of its own (controllers implement generated interfaces, see *API contracts*) |
| `boot` | everything | business logic: it only wires beans, holds `application*.yml` and the integration tests |

- Package roots: `com.irurueta.authserver.authorization` (auth-server), `com.irurueta.authserver.bff`,
  `com.irurueta.authserver.resourceserver`, `com.irurueta.authserver.serviceclient`. Below each root the module
  name is the next package segment (`…authorization.domain`, `…authorization.application`,
  `…authorization.infrastructure.persistence`, `…authorization.api.web`); the `*Application` class lives in the
  root package inside `boot`, so component scanning covers every module.
- A port is an interface in `domain` (named for what it provides, for example `UserAccountRepository`); its
  implementation lives in an `infrastructure/*` adapter. A port implementation never returns `null` (an empty
  `Optional`/`List` instead) and never lets a JDBC, HTTP or framework type escape through it.
- **Domain models are never returned from a controller**; map them onto the DTO generated from the
  contract (or, for an api adapter without a contract, a record in the adapter). The mapper belongs to the adapter,
  never to `domain`.
- Spring Security and Spring Authorization Server types (`UserDetailsService`, `RegisteredClientRepository`,
  `SecurityFilterChain`, …) are framework adapters: they live in `api/*` or `infrastructure/*`, never in `domain`
  or `application`.
- A layer is only created once it has code: an application with no driven adapter or no use case yet has no
  `infrastructure` or `application` module, so `service-client` stays a single `boot` module until #8 gives it a
  domain. `auth-server` has `infrastructure/persistence`, `infrastructure/keys`, `infrastructure/mail` and `infrastructure/sms`;
  `resource-server` has `domain`, `application`, `infrastructure/memory`, `api/web` and `boot`; `bff` has `domain`,
  `application`, `infrastructure/session`, `infrastructure/resourceserver`, `api/web` and `boot`.
- **No demo-only code in `src/main`.** The applications are meant to be reusable and deployable: an endpoint, entity
  or adapter that exists only so a test has something to call lives in `src/test`. The only exceptions are
  `DevDataInitializer` in `infrastructure/persistence`, `DevKeyEncryptionSecret` in `infrastructure/keys` and
  `DevSmsInboxController` with its `DevSmsInboxConfiguration` in `api/web` (`ott` package, the `/dev/sms-inbox` page that
  shows the messages the logging SMS sender kept) of `auth-server`, and `BffDevDatabase` in `bff/infrastructure/session` (all `dev`-profile only, inert elsewhere, and
  their Javadoc says why they cannot live in `src/test`: the end-to-end tests run the packaged jar). The logging
  `SmsSender` and its `SmsOutbox` (`infrastructure/sms`) are the same kind of exception, under the `dev` **or** `test`
  profile only (the end-to-end tests run the jar under `dev`, the integration tests under `test`, which `@PostgresIT`
  activates); with none of `dev`, `test`, `twilio`, `sns` the application refuses to start
  (`MissingSmsGatewayConfiguration`).
- `test-support` (shared Testcontainers base), `e2e-tests` and `coverage` (JaCoCo aggregate) are root modules
  outside the applications.

### Feature layout inside `auth-server`

A feature (an authentication method or capability) spans the layers with **the same package name in each**, so it
can be developed in parallel without editing shared files: `…domain.<feature>`, `…application.<feature>`,
`…infrastructure.persistence.<feature>`, `…api.web.<feature>`. Feature names: `password`, `keys`, `tokens`,
`clients`, `login`, `mfa`, `totp`, `passkeys`, `ott`, `sms`, `social`, `x509`, `implicit`, `account`, `admin`. Each
placeholder package holds a `package-info.java` saying which issue fills it. `mfa` (factor model, policy, lockout,
trusted devices, security events, step-up) and `totp` (authenticator-app second factor and recovery codes) are filled
in every layer (#4), and so is `passkeys` (#5, WebAuthn); and so is `ott` (#6, e-mail / SMS codes and magic links, plus `sms` in the layers that need it); `social`, `x509` and
`implicit` are still placeholders.

### Extension points: adding a login method without editing shared files

- `api.web.login.LoginChainCustomizer` (a functional interface over `HttpSecurity`, deliberately **not** a `Customizer<HttpSecurity>`, because Spring Security applies every such bean to every filter chain): every bean of this type is applied, in
  `@Order`, to the login/UI chain by `SecurityConfig`, **before** its catch-all `anyRequest().authenticated()`, so a
  customizer may still permit its own endpoints. A new method declares one in its own `@Configuration` to enable its
  `HttpSecurity` features (for example `http.oneTimeTokenLogin(...)`); `SecurityConfig` is never edited.
  **Shared objects are chain-wide**: `PasskeyChainCustomizer` sets the login chain's shared `UserDetailsService` to
  `AccountStatusUserDetailsService` (which refuses disabled, locked or expired accounts), so every configurer of that
  chain that reads the shared object (the WebAuthn one today, and a later method's such as one-time tokens) gets the
  account-status check too. A later login method relies on that instead of setting its own; a customizer that replaces
  the shared object changes it for every method of the chain.
- `api.web.login.LoginMethodFragment`: every bean of this type contributes a Thymeleaf fragment (`templateName()`,
  `fragmentName()`, `order()`; `reference()` builds the `template :: fragment` expression) that `LoginController`
  passes to `templates/login.html`, which renders them below the password form.

- `api.web.ProtocolChainCustomizer` (a functional interface over `OAuth2AuthorizationServerConfigurer`, deliberately **not** a `Customizer<...>` bean type for the same reason): every bean of this type is
  applied, in `@Order`, to the protocol chain (`/oauth2/**`, `/.well-known/**`, OIDC endpoints) by
  `SecurityConfig.authorizationServerSecurityFilterChain`, right after OIDC is enabled. A feature declares one in its
  own `@Configuration` to add a converter or provider to a protocol endpoint (for example `x509` or `implicit`);
  `SecurityConfig` is never edited.
- `infrastructure.persistence.clients.AuthorizationJacksonModuleContributor` (a functional interface,
  `JacksonModule module(BasicPolymorphicTypeValidator.Builder validator)`): every bean of this type adds a Jackson
  module to the mapper of the stored authorizations, built by `AuthorizationJsonMapperFactory`, which creates the
  contributed modules **before** `SecurityJacksonModules.getModules(...)` so each can allow its types in the validator
  first. A feature whose authentication or attribute types the framework's modules leave out registers one (the
  passkeys' `WebauthnJacksonModuleContributor` adds `WebauthnJacksonModule`, or the stored principal of a passkey
  sign-in could not be read back at the token request); the factory is never edited. It is deliberately **not** a
  plain `JacksonModule` bean: Spring Boot adds every such bean to the application-wide `JsonMapper`.
- `api.web.tokens.JwtClaimsContributor` (introduced by the token customisation task): every bean of this type adds
  claims, through `IssuedTokenClaims`, to the access tokens of both formats and to the ID tokens:
  `RolesTenantAudienceTokenCustomizer` (the one `OAuth2TokenCustomizer<JwtEncodingContext>`) applies it to the JWTs and
  `ReferenceTokenClaimsCustomizer` (the one `OAuth2TokenCustomizer<OAuth2TokenClaimsContext>`) to the reference tokens,
  so a feature (for example `mfa` adding `amr`) contributes claims without owning a customizer. A contributor checks
  `context.getTokenType()` when a claim belongs to one kind of token only.
- **Authentication factors (`mfa`, #4)**: a login method is also an *authentication factor*, and the MFA framework
  decides, from the factors a session has proved, whether the user may continue. Nothing here is edited by a new
  method; it only registers itself.
  - `domain.mfa.AuthenticationFactor` is a record (`id`, `amrValue`, `authority`, `strength`); `FactorStrength` is
    `PRIMARY`, `PRIMARY_STRONG` (proves identity alone, for example a passkey), `SECOND` (only counts on top of a
    primary) or `REMEMBERED` (stands in for a `SECOND` at sign-in only, today the trusted device; never reported in
    `amr`/`acr`/`auth_time` and never satisfies a step-up: `MfaPolicy.isReported`). The `authority` is the `FACTOR_*` authority that Spring Security 7 `FactorGrantedAuthority` carries for
    the factor (`FACTOR_PASSWORD` is `FactorGrantedAuthority.PASSWORD_AUTHORITY`; `FACTOR_TOTP` is custom) and
    `amrValue` is its RFC 8176 `amr` value (`pwd`, `otp`).
  - Every `AuthenticationFactor` bean is collected by `api.web.mfa.AuthenticationFactorRegistry` (built in
    `mfa.MfaConfiguration`, which also holds `@EnableMultiFactorAuthentication(authorities = {})`); two factors with the
    same authority fail at startup. `PasswordFactor` (`PRIMARY`), `totp.TotpFactor` (`SECOND`) and
    `TrustedDeviceFactor` (`REMEMBERED`, `FACTOR_TRUSTED_DEVICE`) are the existing declarations. The registry answers `findByAuthority`, `withStrength` and `factorsOf(Authentication)`.
  - **Policy**: `domain.mfa.MfaPolicy` is pure and a bean (`application.mfa.MfaConfiguration`).
    `isRequired(clientRequires, userRequires)` is true when the client has `settings.client.mfa.required` (admin API
    `mfaRequired`) or the user requires it; `isSatisfied(factors)` is true for one `PRIMARY_STRONG` factor or a
    `PRIMARY` plus a `SECOND` or `REMEMBERED` one. `api.web.mfa.MfaAuthorizationManager` applies it and, when not
    satisfied, names the registered `SECOND` factors as missing.
  - **"The user requires MFA"** (`application.mfa.IsUserMfaRequiredUseCase`) is `users.mfa_required` (forced by an
    administrator, kept separate) **or** "the user has a confirmed second factor"
    (`HasConfirmedSecondFactorUseCase`, which asks every `application.mfa.SecondFactorEnrolmentQuery` bean; TOTP's is
    `IsTotpEnabledUseCase`; the second one is the passkeys' `HasConfirmedPasskeyUseCase`: a user with a registered passkey
    requires MFA). A later second factor (#6 one-time tokens, #7
    social/x509 when they act as a second factor) extends it by declaring its own `SecondFactorEnrolmentQuery` bean;
    nothing else is edited. The same query decides whether `StepUpGuard` applies.
  - **Enforcement, already wired**: `MfaLoginChainCustomizer` (a `LoginChainCustomizer`, `@Order(0)`) guards
    `/oauth2/consent` and sends a missing `SECOND` authority to `/login/second-factor` through
    `SecondFactorRequiredEntryPoint` (the saved `/oauth2/authorize` request is resumed afterwards);
    `MfaProtocolChainCustomizer` (a `ProtocolChainCustomizer`, `@Order(0)`) does the same inside the authorization
    endpoint validator. A new factor does not touch either.
  - **Step-up**: `StepUpProtocolChainCustomizer` (`ProtocolChainCustomizer`, `@Order(1)`) installs
    `StepUpAuthorizationRequestConverter` first among the `/oauth2/authorize` converters. It reads `acr_values`
    (`AuthenticationContextClass` `pwd` / `mfa` URNs; the `mfa` class satisfies a `pwd` request; unknown values are
    ignored) and `max_age` (seconds since the primary factor was presented) and either lets the request go on, throws
    `SecondFactorRequiredException.forStepUp()` (send to the second-factor page, which then renders the form even on
    a trusted device) or `ReauthenticationRequiredException` (sign in again). `MfaClaimsContributor` (a
    `JwtClaimsContributor`, `@Order(100)`) writes `amr` (factor `amrValue`s in issue order plus `mfa` when two or more
    distinct factors), `acr` and, on access tokens, `auth_time`. Both read the factors only through
    `api.web.mfa.FactorTimeline`: registered, reported (not `REMEMBERED`) factors, and `auth_time` = issue instant of
    the earliest primary factor (else the earliest counted one), so a later second factor never makes a sign-in look
    newer.
  - **API step-up** (RFC 9470): `api.web.mfa.StepUpGuard` is called first by the controllers that remove or reset a
    second factor (`DELETE /api/account/totp`, `POST /api/account/recovery-codes`,
    `DELETE /api/account/trusted-devices/{id}`); while the account has a confirmed second factor it requires the bearer
    JWT's `acr` to be the `mfa` URN and its `auth_time` within `authserver.mfa.step-up-max-age` (default `PT5M`),
    otherwise `MfaExceptionHandler` answers `401` with `WWW-Authenticate: Bearer error="insufficient_user_authentication",
    acr_values=..., max_age=...` and a problem body. `ApiSecurityConfig` is not involved; a new sensitive operation
    calls the guard.
  - `api.web.mfa.SecondFactorFragment`: every bean of this type contributes a Thymeleaf fragment
    (`templateName()`, `fragmentName()`, `order()`, `reference()`) that `SecondFactorController` passes to
    `templates/second-factor.html` (`GET /login/second-factor`, declared in the pages contract), the same shape as
    `LoginMethodFragment`, plus `modelAttributes(Authentication)` (default none) for per-user data, prefixed with the
    factor's name. `TotpSecondFactorFragment` (`templates/totp.html`) is the existing one: it shows the enrolment form
    (QR code, `otpauth` URI, first code posted with `enroll`) to a user without a confirmed authenticator app, which
    `ConfirmTotpAtSignInUseCase` confirms (counted against the lockout), then `GET /login/second-factor/recovery-codes`
    shows the recovery codes once (kept in the session by `PendingRecoveryCodes`) and its Continue link resumes the
    saved request; otherwise the code forms, with a warning at `CountRecoveryCodesUseCase.LOW_THRESHOLD` or fewer
    recovery codes.
  - Shared helpers: `FactorGrantor.grant(authentication, authority)` adds a `FactorGrantedAuthority` (stamped with the
    clock) to an authentication; `SecondFactorUserResolver` resolves the account of the signed-in user; the use cases
    `CheckSecondFactorLockoutUseCase` (reads the user's `second_factor_attempts` row `FOR UPDATE`, so every verification
    use case that starts with it serializes the attempts of that user inside its transaction),
    `RegisterSecondFactorFailureUseCase` (locks after `authserver.mfa.max-failed-attempts`),
    `ResetSecondFactorFailuresUseCase` and `RecordSecurityEventUseCase` give every factor the same lockout and audit
    trail (`SecurityEventAuthenticationEventPublisher` also records the framework's authentication events).
    `TrustedDeviceFilter` (`__Host-TRUSTED-DEVICE` cookie, value `<token>.<HMAC-SHA256 signature>` signed through the
    domain port `TrustedDeviceTokenSigner`, implemented by `HmacTrustedDeviceTokenSigner` in `infrastructure/keys`;
    only the token's SHA-256 hash is persisted in `trusted_devices`) looks at the cookie only on
    `GET /login/second-factor`, where `FindTrustedDeviceUseCase` verifies the signature before any lookup, then grants
    `FACTOR_TRUSTED_DEVICE` to a remembered browser, changes the session id and resumes the saved request; disabling
    the second factor revokes every trusted device of the user. Recovery codes are generated and accepted only while
    the account has a confirmed second factor (`HasConfirmedSecondFactorUseCase`).
  - Settings: every `authserver.mfa.*` key is bound once into the validated `@ConfigurationProperties` record
    `application.mfa.MfaProperties` (invalid values fail at startup) and injected; never read one with `@Value`. The
    client's `mfaRequired` flag is read only through `IsClientMfaRequiredUseCase` (the custom setting's key lives in
    `RegisteredClientMapper` alone).
  - Keys derived per purpose: `PurposeKeyDerivation` (`infrastructure/keys`) derives a distinct salt/key from the
    key-encryption secret per purpose (`totp-secret` for `AesGcmTotpSecretCipher`, `trusted-device-cookie` for the
    cookie signer); `AesGcmKeyCipher` keeps the configured salt so stored signing keys still decrypt. A new use of the
    secret takes a new purpose label, never the signing-key key. A second-factor filter changes the session id (and renews the CSRF token) on
    success: `TotpChainCustomizer` hands the chain's shared `SessionAuthenticationStrategy`, the form login's, to
    `TotpAuthenticationFilter`.
  - **How a later factor (for example `ott`, `social` or `x509`) registers**, with no shared file edited:
    1. an `AuthenticationFactor` bean (a `@Configuration` with a `@Bean` like `TotpFactor`) with its `FACTOR_*`
       authority, `amr` value and strength;
    2. a `LoginChainCustomizer` bean (`@Order` above the existing ones) that permits its own endpoints and adds its
       filter before `AuthorizationFilter` (see `TotpChainCustomizer`, wired by `TotpConfiguration`);
    3. for a `SECOND` factor, a `SecondFactorFragment` bean and its `templates/<method>.html` fragment (with
       `modelAttributes` for its enrolment or warnings) and a `SecondFactorEnrolmentQuery` bean; a primary factor adds
       a `LoginMethodFragment` instead;
    4. an `AuthenticationProvider` that verifies the credential (through use cases, using the lockout and event use
       cases above) and returns the authentication with the factor added through `FactorGrantor` (see
       `TotpAuthenticationProvider`, driven by a `ProviderManager` inside its own filter);
    5. its migration in its own Flyway range. Claims, step-up and the policy then pick the factor up by authority.
- **Passkeys (`passkeys`, #5)**: the reference for a `PRIMARY_STRONG` factor, built on Spring Security's `http.webAuthn(...)`
  (no hand-rolled ceremony) and registered through the extension points above. The shared files it still touches,
  and why: the `pages` group of `OpenApiConfig` (to publish `/account/passkeys`), `application.yml` (the
  `authserver.passkeys.*` settings), `messages.properties` (the texts of its fragments and page),
  `PasswordAuthenticationIT` (the login page now carries the passkey fragment), `TotpSecondFactorFragment` and
  `totp.html` (the TOTP enrolment is not offered to a user whose passkey already completes the second factor), the
  two API contracts and `apis/README.md`, the poms of `api/web` and `infrastructure/persistence` (the WebAuthn
  dependency), and the new `AuthorizationJacksonModuleContributor` extension point (added once so the passkeys no
  longer edit `AuthorizationJsonMapperFactory`).
  - `PasskeyFactor` (`FACTOR_WEBAUTHN`, `amr` `hwk`, `PRIMARY_STRONG`, so a passkey alone satisfies `MfaPolicy`; after a
    password it adds to `FACTOR_PASSWORD` because Spring merges the authorities of a re-authentication of the same
    user name, and `amr` is `pwd`, `hwk`, `mfa`); `PasskeyConfiguration` returns the `PasskeyChainCustomizer`
    (`LoginChainCustomizer`, `@Order(2)`); `PasskeyLoginMethodFragment` and `PasskeySecondFactorFragment` are the two
    fragments; `passkeys.js` is the only browser script (conditional-mediation autofill, button, registration).
  - `PasskeyRegistrationFilter` guards `/webauthn/register/**` with the MFA policy (Spring's creation-options filter answers
    before the chain's authorization filter). `DELETE /webauthn/register/**` is denied: a passkey is removed only through
    `DELETE /api/account/passkeys/{id}`, which calls `StepUpGuard`; deleting the last passkey of an account that has no
    other confirmed second factor revokes its trusted devices (`DeletePasskeyUseCase`, as `DisableTotpUseCase` does).
    The account page is `GET /account/passkeys`. The URLs of the WebAuthn endpoints reach `passkeys.js` as `data-*`
    attributes rendered with `@{...}`; the script never redirects after a failed automatic (conditional) sign-in.
  - **Lockout**: `PasskeySecondFactorLockoutFilter` (built by `PasskeyChainCustomizer`, not a bean; added before
    `BasicAuthenticationFilter`, where the WebAuthn configurer later puts its authentication filter, so it runs first)
    answers `401` to `POST /login/webauthn` when the session already holds a signed-in user (the passkey completes a
    second-factor step) and `CheckSecondFactorLockoutUseCase` reports that user locked; a passwordless sign-in is not
    affected. Failed passkey assertions are deliberately **not** counted as second-factor failures: an assertion is a
    signature over a fresh challenge by a key that never leaves the authenticator, so it cannot be guessed, and
    counting cancelled ceremonies would only let users lock themselves out of their other factors.
  - `AccountStatusUserDetailsService` wraps the user service of the WebAuthn chain: Spring's provider never checks the
    account status, so without it a disabled account could sign in (it is the chain's shared `UserDetailsService`, see
    `LoginChainCustomizer` above). `WebauthnJacksonModuleContributor` (an `AuthorizationJacksonModuleContributor`)
    adds `WebauthnJacksonModule`, or the stored principal of a passkey sign-in cannot be read back at the token request.
  - Credentials live in Spring's `JdbcPublicKeyCredentialUserEntityRepository` / `JdbcUserCredentialRepository`
    (`WebAuthnJdbcConfiguration`); the management API reads them through the domain port `PasskeyRepository`.
    `Passkey.id` is the base64url credential id and `userId` the WebAuthn user handle, both strings, never uuids.
    `V500` keeps Spring's columns but makes `user_entities.name` unique and `created`/`last_used`
    `timestamp with time zone`; `PasskeyRepository.existsForAccount` answers the enrolment query in one statement.
    A refused label is `InvalidPasskeyLabelException` (`400 invalid-label`), never a bare `IllegalArgumentException`.
  - Settings: `authserver.passkeys.rp-name`, `rp-id` and `allowed-origins`, bound into `PasskeyProperties` (default
    `localhost`: a deployment must set its public host).
  - **Gap, passkey-first sign-up**: not possible with the Spring APIs used. Registration (`/webauthn/register/**`) needs an
    authenticated session, so a user first signs in with a password (or any other primary factor) and then registers a
    passkey on `/account/passkeys`; an account cannot be created with a passkey and no password.
  - **Known limitations** (they need a shared-file or design decision): a passkey-only session gets `acr` = the password URN
    (`MfaClaimsContributor` reports `mfa` only for two distinct factors), so it cannot satisfy `StepUpGuard` and must
    re-authenticate with a second factor; `Webauthn4JRelyingPartyOperations` hardcodes user verification to `PREFERRED`;
    `lastUsedAt` equals `createdAt` until the first use, because Spring's schema requires `last_used`.
- **One-time tokens (`ott` and `sms`, #6)**: e-mail codes, magic links and SMS codes, as a primary sign-in and as a second
  factor, built on Spring Security's `http.oneTimeTokenLogin(...)` (`POST /ott/generate`, `POST /login/ott`, framework
  endpoints) and registered through the extension points above. Four `AuthenticationFactor` beans (`OttFactors`):
  `FACTOR_OTT` (Spring's constant, `amr` `otp`, `PRIMARY`: e-mail code or link as the sign-in), `FACTOR_OTT_SMS` (`amr`
  `sms`, `PRIMARY`), `FACTOR_OTT_EMAIL_2FA` (`otp`, `SECOND`) and `FACTOR_OTT_SMS_2FA` (`sms`, `SECOND`). The second-factor
  variants are separate authorities so a code used to sign in is never also counted as the second factor.
  - **Flows**: sign-in asks `POST /ott/generate` (identifier and channel; the answer is always the same redirect to
    `/login/ott`, whether the account exists, is enabled or has a verified phone, so nothing reveals accounts); the code
    is bound to the session (`PendingOtt`) and submitted to `POST /login/ott` (`OttCodeAuthenticationProvider`); a magic
    link opens `GET /login/ott/confirm`, whose button POSTs the token (a link is never consumed by a GET, so mail
    scanners cannot spend it; `OttLinkAuthenticationProvider`). As a second factor the code is posted to
    `POST /login/second-factor/ott` (`OttSecondFactorFilter`, which changes the session id and renews CSRF as the TOTP
    one does), offered by `OttSecondFactorFragment`. Which channels may be a user's second factor is one rule,
    `OttSecondFactorChannels`, enforced in all three places (the fragment, the delivery in
    `OttGenerationSuccessHandler`, which answers the same redirect but sends nothing, and the acceptance in
    `OttSecondFactorAuthenticationProvider` and the second-factor branch of `OttLinkAuthenticationProvider`): never the
    channel that signed the user in; SMS only with a verified phone; **e-mail (`FACTOR_OTT_EMAIL_2FA`, code or link)
    only while the user has no other confirmed second factor** (`HasConfirmedSecondFactorUseCase` false, which includes
    the verified phone), because the password is reset by e-mail too and a mailbox must never stand in for a stronger
    factor. The allowed channels are passed into `VerifyOneTimeCodeUseCase` *before* the code is compared, so a code of
    another channel is burnt, counted by the shared second-factor lockout and never audited as a success. A magic link
    cannot confirm a second factor outside the primary-factor session (`PrimaryFactorSession`), and a second-factor
    link is not delivered for a user name longer than `LinkTokenUsername.MAX_SECOND_FACTOR_LENGTH` (it would not fit
    next to the marker). Consequence: a user whose only second factor is the phone and who signs in by SMS has no
    one-time token left as second factor.
  - **Delivery**: no mail server or SMS gateway is ever called inside a transaction or on the request thread. The use
    cases store what they must and publish an event (`EmailCodeRequested`, `EmailLinkRequested`, `SmsRequested`;
    `toString` hides addresses and codes); `api.web.ott.OttDeliveryListener` handles them with
    `@TransactionalEventListener(phase = AFTER_COMMIT, fallbackExecution = true)` plus `@Async` and calls
    `DeliverOneTimeTokenUseCase` (`@Transactional(propagation = NOT_SUPPORTED)`: remote calls only), logging a failure
    without address, number or token. Known and unknown identifiers therefore answer in the same time, and a slow
    gateway holds no pooled connection. `api.web.AsyncConfiguration` enables `@Async` once (Spring Boot's
    `applicationTaskExecutor`), as `SchedulingConfiguration` does for scheduling. Integration tests that read Mailpit or
    the SMS outbox wait for the message (`MailpitClient.awaitMessageTo`, `AbstractOttFlow.awaitSmsCount`).
  - **Phone**: `user_phones` holds one verified E.164 number per user (unique); enrolment sends a verification code
    (`StartPhoneEnrolmentUseCase`, same answer for a number that belongs to someone else). It is managed with
    `GET/PUT/DELETE /api/account/phone` and `POST /api/account/phone/verify` (starting an enrolment and removal call
    `StepUpGuard`, a no-op while the account has no confirmed second factor) and with the session page
    `GET /account/phone` (`PhonePageController`, guarded by `PhonePageChainCustomizer` `@Order(4)` behind the MFA policy,
    form posts under `/account/phone/**`, `PhoneSessionStepUp` for the enrolment and the removal). A verified phone is a
    confirmed second factor (`HasVerifiedPhoneUseCase` as a `SecondFactorEnrolmentQuery`), so a user with a phone requires
    MFA. `RemovePhoneUseCase` audits `SECOND_FACTOR_REMOVED` and revokes the trusted devices when no second factor is
    left (as `DeletePasskeyUseCase`); `ConfirmPhoneUseCase` treats a new number over a verified one as a replacement:
    audited the same and always revoking the trusted devices (as `DisableTotpUseCase`). `JdbcUserPhoneRepository.save`
    takes a PostgreSQL advisory lock on the number in the caller's transaction, so the unique constraint is never hit
    (a violation would abort the transaction).
  - **SMS gateways** (module `infrastructure/sms`): the domain port `SmsSender` has three implementations selected by a
    Spring profile, never by a property: `twilio` (`TwilioSmsSender`, `TwilioProperties` bound from
    `AUTHSERVER_SMS_TWILIO_*` through `application-twilio.yml`), `sns` (`SnsSmsSender`, AWS SDK v2 default credential
    chain, `application-sns.yml`) and, **only under `dev` or `test`**, `LoggingSmsSender` (a bounded in-memory
    `SmsOutbox`, nothing leaves the process). The profile expressions (`twilio & !sns`, `sns`,
    `(dev | test) & !twilio & !sns`) guarantee at most one `SmsSender`, and `MissingSmsGatewayConfiguration`
    (`!dev & !test & !twilio & !sns`) stops the startup with a message naming the profiles, so a deployment never
    silently keeps its messages in memory; `SmsSenderProfilesIT` checks the selection. Every gateway failure is an
    `SmsDeliveryException` carrying neither the number nor the code. `LibPhoneNumberNormalizer` (libphonenumber)
    implements `PhoneNormalizer`, and `LibPhoneNumberCountryResolver` the domain port `PhoneCountryResolver`.
  - **Cost control**: `SmsCostPolicy` (domain, a bean) checks `authserver.sms.allowed-countries`, and
    `SendSmsOneTimeCodeUseCase` reserves the cost with `SmsCostLedgerRepository.tryRecord(sentAt, country, cost,
    windowCap, dailyCap)` (`SmsSpendCap`s from the policy): one conditional insert after a PostgreSQL transaction-level
    advisory lock, so concurrent senders never overshoot a cap and a refused message leaves no row; only then is the
    `SmsRequested` event published. The ledger is purged by `OttCleanupJob` (with expired codes, verifications and
    Spring's `one_time_tokens`, through `CleanupOttUseCase` and the domain port `domain.ott.ExpiredLinkTokenPurger`;
    cron `authserver.ott.cleanup.cron`).
  - **Rate limits**: `OttRateLimitFilter` / `OttRateLimiter` (Bucket4j + Caffeine, per client address and per identifier,
    `authserver.ott.rate-limit.*`) answer `429`; the filter is added before Spring's `GenerateOneTimeTokenFilter` (which
    answers `POST /ott/generate` itself, so a filter placed before `UsernamePasswordAuthenticationFilter` would never see it,
    which `OttRateLimitIT` checks); the window logic is the shared `api.web.ratelimit.FixedWindowBuckets`, also
    used by `AccountRateLimiter` so the two do not duplicate it.
  - **Extension points used**: `OttChainCustomizer` (`LoginChainCustomizer`, `@Order(3)`, built in `OttConfiguration`),
    `OttLoginMethodFragment` (`LoginMethodFragment`, `login-ott.html`, order 300), `OttSecondFactorFragment`,
    `SecondFactorEnrolmentQuery`, `FactorGrantor`, the lockout and security-event use cases; `OttGenerateRequestResolver`
    sets the link lifetime from `OttPolicy`. Settings: `authserver.ott.*` (`OttProperties`) and `authserver.sms.*`
    (`SmsProperties`), tagged `ott-config` / `sms-config` in `application.yml`.
  - **Shared files it still touches, and why**: the `pages` group of `OpenApiConfig`, the two contracts and `apis/README.md`,
    `application.yml` (settings) and the two profile files, `messages.properties`, `PasswordAuthenticationIT` (the login page
    carries the OTT fragment), `AccountRateLimiter` (now uses `FixedWindowBuckets`), `MfaClaimsContributorTest`,
    `spotbugs-exclude.xml` (an `OttSecondFactorToken` entry as for `TotpAuthenticationToken`, and two narrow
    `RV_RETURN_VALUE_IGNORED_NO_SIDE_EFFECT` entries for untouched customizers that the detector flags once
    `OneTimeTokenLoginConfigurer` is referenced), the poms (module registration, libphonenumber, Twilio, AWS SDK BOM, Thymeleaf
    in `infrastructure/mail`), `docs/antora.yml`, `coverage/pom.xml`, `MailConfiguration` (the `ThymeleafOttMailer` bean),
    `api.web.AsyncConfiguration` (new, the one switch for `@Async`) and `test-support`'s `@PostgresIT` (activates the
    `test` profile, which the logging SMS sender needs).
  - **Design decisions and limits a reviewer should see**: Spring's `JdbcOneTimeTokenService` always issues a UUID, so the
    link token is Spring's and the numeric code is ours (`ott_codes`, only the hash stored, constant-time compare); its link
    token carries neither channel nor purpose, so `OttLinkAuthenticationProvider` consumes the token itself and reads the
    purpose from the stored user name (`LinkTokenUsername`, a control-character marker for a second-factor link), and links
    are sent by e-mail only (no SMS link). The `application` layer does not log (no `org.slf4j` there): refusals are
    swallowed by the use cases, delivery failures are logged by `OttDeliveryListener` and an exhausted SMS budget by
    `JdbcSmsCostLedgerRepository`; `OpenApiDriftIT` leaves the `/dev/` pages out of the comparison because `/dev/sms-inbox` exists only under the
    `dev` profile and is not part of the published contract. The dev inbox reads the outbox through the domain port `SmsInbox`
    (an `api/*` module cannot see `infrastructure/sms`). Failed code attempts are counted and lock the second factor, and each
    code is spent after `authserver.ott.max-attempts`. Mail is plain Thymeleaf text/HTML from `mail/ott-*.html|txt`, locale from
    `MailProperties`.
- `api.web.ApiSecurityConfig`: the stateless `/api/**` chain (`@Order(0)`, errors per RFC 6750) with a decoder of its
  own over the published keys: issuer, timestamps, `aud` containing `authserver.api.audience` (default `auth-server`),
  and no `purpose` claim. Never make that decoder the framework-wide `JwtDecoder` bean, which the UserInfo endpoint
  uses for tokens of other audiences. Its public paths and the `/api/admin/**` rule (scope `admin` only) are fixed
  there; a feature only adds controllers under `/api/**`.
- `api.web.AsyncConfiguration` enables `@Async` once for every feature (Spring Boot's `applicationTaskExecutor`); a
  feature never enables it itself.
- `api.web.SchedulingConfiguration` enables `@Scheduled` once for every feature; a feature declares its job (a
  `@Component` with a `@Scheduled` method calling a use case) and never enables scheduling itself.

A later issue therefore adds a login method by creating its feature packages (domain model and port, use case,
persistence adapter, web `@Configuration` with its controller, a `templates/<method>.html`, a `LoginChainCustomizer`
bean and a `LoginMethodFragment` bean), plus its own Flyway migration in its range. No existing file needs to change.

### Flyway ranges

Migrations live in `auth-server/infrastructure/persistence/src/main/resources/db/migration`
(`classpath:db/migration`). The skeleton (#1) uses `V100`–`V199` (`V100` Spring Authorization Server schema, `V101`
users). Used so far: `V200` account, `V210` signing keys, `V230` consumed refresh tokens, `V240` authorization creation time,
`V400` MFA security events, per-user MFA flag and second-factor attempts, `V410` TOTP credentials and recovery codes, `V420`
trusted devices, `V500` WebAuthn schema (Spring's `user_entities` and `user_credentials`, which already hold `label`,
`created` and `last_used`), `V600`–`V699` one-time tokens: `V600` Spring's `one_time_tokens`, `V610` `ott_codes`, `V620`
`user_phones`, `V630` `sms_cost_ledger`. Each issue states its own
range in its body; never write a migration outside it. The `bff` has its own database (`bff`) and its own Flyway
history: `V300` (Spring Session schema) lives in `bff/infrastructure/session/src/main/resources/db/migration`.

### Key encryption secret

- Private signing keys are encrypted at rest from `authserver.keys.encryption.password` and `.salt` (hex). With the
  `dev` profile `DevKeyEncryptionSecret` generates them once per machine under `~/.irurueta-auth-server/` (owner-only
  file, never inside the repository). Without `dev` they must be supplied, normally through the environment variables
  `AUTHSERVER_KEYS_ENCRYPTION_PASSWORD` and `AUTHSERVER_KEYS_ENCRYPTION_SALT`; tests pass runtime-generated values.

### API contracts

**Every HTTP endpoint the application itself handles, JSON or HTML page, is defined first in an OpenAPI contract
under `apis/<app>/`, and its controller only implements the interface openapi-generator produces. Never put a mapping
annotation (`@RequestMapping`, `@GetMapping`, `@PostMapping`, `@PutMapping`, `@PatchMapping`, `@DeleteMapping`) in
hand-written code.** The contracts are the source of truth (see `apis/README.md`).

- **JSON endpoints**: `apis/<app>/rest-server/<app>-api-v1.yaml`. Add the operation (every operation, parameter,
  schema and property described, every constraint expressed), regenerate
  (`./mvnw -pl <app>/api/web -am generate-sources`) and implement the generated interface in a controller that calls
  use cases. openapi-generator (`spring`, `interfaceOnly`, records, Spring Boot 4, Jackson 3, Bean Validation)
  generates the interfaces and DTOs into each `api/web` module's `target/generated-sources` (packages
  `…api.web.v1.generated.{api,model}`). Never hand-write a web DTO: a `@Component` mapper per feature (for example
  `ClientDtoMapper`) in the api adapter converts between generated DTOs and the domain; problem details go through
  `ProblemJsonExceptionHandler` or the feature's scoped `@RestControllerAdvice`.
- **HTML pages**: `apis/<app>/web-pages/<app>-pages-v1.yaml` (today `auth-server-pages-v1.yaml`: `/login`,
  `/login/second-factor`, `/login/second-factor/recovery-codes`, `/account/passkeys`, `/account/phone`, `/login/ott`, `/login/ott/confirm`, `/dev/sms-inbox` (dev only), `/oauth2/consent`, `/logout`), generated into `…api.web.pages.v1.generated.api`. Each operation answers
  `text/html`; its controller renders the Thymeleaf template with `PageRenderer` (`api.web.pages`), which resolves the
  view with the request's locale, renders it against the current request (CSRF fields, `@{}` links and messages keep
  working) and adds the branding. The pages are published by the springdoc group `pages` (`/v3/api-docs/pages`) and
  compared with their contract by `OpenApiDriftIT`.
- **Calls to another service** go through a client generated from that service's contract (`java` generator,
  `library=restclient`, into `…infrastructure.<adapter>.v1.generated`), behind a domain port implemented in an
  `infrastructure/*` adapter that translates every failure into a domain exception (for example
  `RestDocumentGateway` in `bff/infrastructure/resourceserver`). There is no generic pass-through relay: every
  operation an application exposes is in its own contract.
- **Exempt** are only the endpoints owned by frameworks: the Spring Security filters (`POST /login`, `POST /logout`,
  `POST /bff/logout`, `/oauth2/**`, `/login/oauth2/**`, and the `webAuthn` ones: `/webauthn/**`, `POST /login/webauthn`), the Spring Authorization Server protocol endpoints
  (`/oauth2/**`, `/.well-known/**`, `/connect/**`, `/userinfo`), Spring Boot's `BasicErrorController` (`/error`,
  customised only through an `ErrorViewResolver` bean) and actuator.
- Generated code is never committed or edited, and is excluded from Checkstyle, PMD/CPD, SpotBugs, JaCoCo and Sonar.
- **Enforced**: `HexagonalArchitectureTest` in each application's `boot` module fails when a hand-written class or
  method (outside a `..generated..` package) carries a mapping annotation, or a `@Controller`/`@RestController` does
  not implement an interface from a `..generated.api..` package; `OpenApiDriftIT` fails when a document springdoc
  serves differs from its contract.

## Conventions

- Every source file starts with the Apache 2.0 header used in the existing files.
- Never commit secrets, keys or certificates: generate dev keys at first start and test keys inside the tests.
- Code shown in the docs guide is wrapped in tag comments, see below. Never rename or remove a tag without updating
  the docs repository.
- A new endpoint, JSON or HTML page, and a call to another service start in a contract under `apis/` (see *API
  contracts* above); a mapping annotation in hand-written code fails the build.

### Tag-comment convention

Code included by the docs guide is wrapped in `tag::<feature>-<what>[]` / `end::<feature>-<what>[]` markers
(lowercase kebab-case, feature first, for example `security-chains`, `login-form`, `sas-schema`, `bff-user`). The
comment syntax follows the file type: `// tag::x[]` in Java, `-- tag::x[]` in SQL, `# tag::x[]` in YAML/properties and
`<!-- tag::x[] -->` in HTML/XML. Antora includes them with
`include::irurueta-auth-server::example$<module-path>/src/...[tag=x]`, where `<module-path>` is the module's directory
from the repository root (for example `auth-server/api/web`). The Antora Collector copies each module's `src/**`
(plus the root `pom.xml` and `compose.yaml`) into the `example$` family; `docs/antora.yml` holds one scan per module,
so a new module needs a new scan there.

## Testing

### Assertions: JUnit, not AssertJ

Use `org.junit.jupiter.api.Assertions` only. Do **not** add AssertJ to a test unless something genuinely cannot be
expressed without it, and say why in the test's javadoc if you do.

```java
// Yes
assertEquals(expected, actual);
assertSame(expected, actual);
assertTrue(result.isEmpty());
final var error = assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername("x"));
assertTrue(error.getMessage().contains("x"));

// No
assertThat(actual).isEqualTo(expected);
assertThatThrownBy(() -> service.loadUserByUsername("x")).isInstanceOf(UsernameNotFoundException.class);
```

MockMvc's own `andExpect(...)` matchers and Hamcrest matchers passed to them are fine: they are MockMvc's API, not an
assertion library.

### Test doubles: Mockito, never hand-written fakes

Do **not** write `Fake*`/`Stub*` classes or anonymous implementations of a port or interface in a test. Use Mockito
mocks or spies.

```java
@ExtendWith(MockitoExtension.class)
class FindUserAccountUseCaseTest {

    @Mock
    private UserAccountRepository userAccountRepository;

    @InjectMocks
    private FindUserAccountUseCase useCase;
```

- Prefer `@InjectMocks` over a `@BeforeEach` that news up the subject by hand.
- Use an `ArgumentCaptor` when a test needs to prove the *same instance* was passed through: records have value
  equality, so `verify(port).method(query)` alone does not prove identity.
- Build a captor with `ArgumentCaptor.captor()`, never `ArgumentCaptor.forClass(...)`, which yields a raw type for
  generic arguments: `final var captor = ArgumentCaptor.<List<UUID>>captor();`. A `@Captor` field is fine too.
- Spring test slices replace beans with `@MockitoBean`, never with a hand-written `@TestConfiguration` double.
  Real in-memory framework implementations used as *test data* (for example an `InMemoryRegisteredClientRepository`
  holding one client for a slice test) are not doubles of this repository's own ports and are allowed.

### Test method naming

```
void methodBeingTested_whenCondition_expectedResult()
```

```java
void loadUserByUsername_whenUserIsMissing_throwsUsernameNotFoundException()
void constructor_whenUsernameIsBlank_throwsIllegalArgumentException()
void loginSecurityFilterChain_whenCustomizerPermitsPath_doesNotRedirectToLogin()
void equalsAndHashCode_whenFieldsMatch_areEqual()
```

- For a record's canonical constructor use `constructor`; for a static factory use its own name; for value
  semantics use `equalsAndHashCode`; for an HTTP endpoint test name the handler method or the path segment.
- Checkstyle's `MethodName` check forbids underscores, so `checkstyle.xml` carries a `SuppressionSingleFilter` scoped
  to `.*(Test|IT)\.java$`. Production method names stay camelCase; do not widen that suppression.

### Test class layout

- **One test class per production class.** Do not group several production classes into one test class.
- **Order methods public → private.** Fields and setup first, then `@Test` methods, then private helpers last.
- **Nested types go last** (see *Member order* under Java style). A nested configuration class of a test stays
  package-private: the test class's own `@Import` cannot name a private nested class, and Spring's test context
  only detects non-private nested configuration classes. Say so in its Javadoc.

### Unit tests are `*Test`, integration tests are `*IT`

| Plugin | Includes | Phase | What belongs there |
|---|---|---|---|
| Surefire | `**/*Test.java` | `test` | Unit tests: no Spring application context, no Docker |
| Failsafe | `**/*IT.java` | `verify` | Integration tests: a Spring context, Testcontainers or the packaged jars |

**Any class carrying `@SpringBootTest` or a Spring test slice (`@WebMvcTest`, `@JdbcTest`, `@DataJdbcTest`, …), or
starting a container, is an integration test: name it `*IT.java`, never `*Test.java`.** `mvn test` must stay a fast
unit-test run; `mvn verify` runs both. JaCoCo's `prepare-agent-integration` writes `jacoco-it.exec` and the
`coverage` module merges every `jacoco*.exec`, so moving a test to `*IT` does not drop its coverage out of the gate.

### Shared test infrastructure

- `test-support` holds `OpenApiContract`, `PostgresTestConfiguration` (a `postgres:18` Testcontainers container exposed through
  `@ServiceConnection`) and the `@PostgresIT` meta-annotation: `@SpringBootTest` wired to that container, with the
  `test` profile active (it selects test-only adapters such as the logging SMS sender; a class that declares
  `@ActiveProfiles` itself replaces it) and a `webEnvironment()` attribute for `RANDOM_PORT` tests. Consumers depend on it with `<scope>test</scope>`. It also holds the
  Mailpit support of the one-time token tests: `Mailpit` (the image, pinned to a version tag, never `latest`, and a factory
  for the container and for its client), `MailpitClient` (reads the received e-mail through the Mailpit HTTP API: the code
  or the magic link of a message) and `MailpitTestConfiguration` (a Spring test configuration that starts the container and
  points `spring.mail.*` at it; import it next to `@PostgresIT`, as `AbstractOttFlow` does).
- `e2e-tests` drives the packaged `auth-server` and `bff` boot jars through headless Chromium with Playwright for
  Java (chosen over Selenium because it manages its own browser binaries, auto-waits for elements and needs no
  driver setup). It must stay last in the reactor, before `coverage`.
- `OpenApiContract` (test-support) summarizes an OpenAPI contract and a served document; `OpenApiDriftIT` in each
  `boot` module compares `apis/<app>/rest-server/<app>-api-v1.yaml` with `/v3/api-docs` and, in `auth-server`,
  `apis/auth-server/web-pages/auth-server-pages-v1.yaml` with `/v3/api-docs/pages` (operations, status codes,
  parameters, bodies, security, schemas). To change an API or a page, edit the contract; there is nothing else to
  regenerate or commit. springdoc only documents its groups (see each `OpenApiConfig`): `api` (`/api/**` in
  `auth-server` and `resource-server`, `/bff/**` and `/api/**` in `bff`) and, in `auth-server`, `pages` (`/login`,
  `/login/second-factor`, `/login/second-factor/recovery-codes`, `/account/passkeys`, `/account/phone`, `/login/ott`, `/login/ott/confirm`, `/dev/sms-inbox` (dev only), `/oauth2/consent`, `/logout`). Put every new endpoint under one of them, or widen the group.
- The `dev` profile of `auth-server` resolves `../../compose.yaml` against the working directory (`spring-boot:run`
  uses the `boot` module directory); elsewhere, set `SPRING_DOCKER_COMPOSE_FILE` to the root `compose.yaml`.

## Java style

- **Member order** (the Java Code Conventions order, plus nested types last as IntelliJ's default arrangement and
  most style guides do): static fields, instance fields, constructors, methods (public → private), then nested
  types. A nested type is `private` unless code outside the enclosing class, or a framework that requires it,
  needs to see it.
- **Records** for immutable types (domain models, value objects, web DTOs); validate in the compact constructor and
  defensively copy collections (`List.copyOf(...)`), or SpotBugs `EI_EXPOSE_REP` fails the build.
- **`final`** on parameters (Checkstyle enforces it) and on locals; **`final var`** is the default for locals.
- **Type inference**: prefer `var` with an explicit type witness over a declared type for generic static factories:
  `final var empty = List.<String>of();`, not `final List<String> empty = List.of();`.
- **Full Javadoc** on every type, method, constructor and field, including in test sources (Checkstyle runs with
  `includeTestSourceDirectory=true`).
- **Named constants, never magic numbers**: `MagicNumber` is on and also applies to tests. Put the constant on the
  type that owns the rule.
- **Streams over loops for a simple scan**: `items.stream().anyMatch(Objects::isNull)`.
- **Modern collection accessors**: `items.getFirst()` / `items.getLast()`, never `items.get(0)` /
  `items.get(items.size() - 1)`.
- **Method references over lambdas** where the lambda only forwards its own parameter to one method
  (`names.forEach(log::info)`, not `names.forEach(name -> log.info(name))`). Keep a lambda when it does more.
- **`switch` over chained conditions** when one value is tested against several alternatives; use a `switch`
  expression when the result is a value. Chained `if`s stay for ranges or tests over different values.
- **No redundant `this`.** Drop `this.` wherever the field is not shadowed; keep it only in a constructor whose
  parameter deliberately shares the field's name (removing it there is a silent self-assignment).
- **Utility predicates over multi-branch conditions**: Spring's `StringUtils.hasText(value)` instead of
  `value == null || value.isBlank()`, `CollectionUtils.isEmpty(list)` instead of `list == null || list.isEmpty()`.
  They are on every module's classpath except `domain`, which uses its own `domain.Preconditions`
  (`requireText`, `requireTextIfPresent`, `isBlank`) so a compact constructor has no null-or-blank branches.
- **Transactions belong to the use cases.** Every `*UseCase` of `auth-server` is `@Transactional` (`readOnly = true`
  when it only reads), on the class or on each public method; its `HexagonalArchitectureTest` fails the build
  otherwise. The use cases of `resource-server` and `bff` touch no transactional store (in-memory documents, and the
  resource server behind a remote call) and carry none: a transaction there would only hold a connection across a
  remote call. Adapters never
  open a transaction of their own: a repository method with several statements runs in its caller's (the advisory
  lock's `TransactionTemplate` in `JdbcSigningKeyRepository` joins it). Only non-use-case entry points such as
  `DevDataInitializer` demarcate their own.
- **Mappers are classes.** A conversion between layers or types (domain model ↔ web DTO, ↔ framework type such as
  `UserDetails`, `RegisteredClient` or `JWK`, ↔ database row) lives in an explicit mapper of the adapter (a
  `@Component` named `*Mapper`, or a `RowMapper<T>` class), injected and unit-tested on its own; never a private
  static `toX`/`map` method inside a controller, repository or `@Configuration`. Mappers never live in `domain`.
- **Collaborators are beans.** A use case never `new`s a policy, generator or strategy: it is declared as a `@Bean`
  (for a domain type, in a `@Configuration` of `application`) and injected, so it can be replaced and mocked. Tests
  that need the real behaviour use `@Spy` with a real instance.
- **Don't reinvent infrastructure.** Rate limiting, retries, circuit breakers and caches use an established library
  (Bucket4j, Resilience4j, Caffeine), never hand-written counters, maps or loops; check for one before writing it.

### Lombok

- **Constructors**: a constructor that only assigns its parameters to `final` fields is replaced by
  `@RequiredArgsConstructor` (or `@AllArgsConstructor`/`@NoArgsConstructor`/`@Value`/`@Data` where they say the same
  thing more briefly). Keep a hand-written constructor only when it does real work: it validates with a specific
  exception type (a record rejecting a blank value with `IllegalArgumentException`), defensively copies, or derives
  something once at construction. Spring beans (use cases, adapters) take `@RequiredArgsConstructor`: Spring never
  injects `null`, so they don't null-check their dependencies.
- **Loggers**: `@Slf4j`, never a hand-rolled `LoggerFactory.getLogger(Foo.class)` field. The generated field is
  `log`.
- `@Configuration` classes with only `@Bean` methods need no constructor at all.

### Line endings are LF, and never the platform's own

Every file uses `\n`; `.gitattributes` pins `* text=auto eol=lf`. Code must never ask the platform what a newline
is: no `System.lineSeparator()`, `String.format("%n")`, `PrintWriter.println`, `BufferedWriter.newLine()` or
Jackson's `writerWithDefaultPrettyPrinter()` (pass `new DefaultIndenter("  ", "\n")`). Anything that compares
file content exactly (the API contracts and the tagged regions the docs include) must produce identical bytes on Linux, macOS and Windows.

### Locales are pinned, and never the platform's own

A response's language is a property of the request and a test's expected text is a property of the test, never of
the machine. Pass an explicit locale (`Locale.ROOT` for machine-facing text) to `toUpperCase`/`toLowerCase`,
`String.format`, `DateTimeFormatter` and `NumberFormat`. `application.yml` sets
`spring.messages.fallback-to-system-locale: false` and `spring.web.locale: en`, and a test asserting on localized text
sets `LocaleContextHolder.setLocale(Locale.ENGLISH)` first.

## Build gates

`./mvnw -B clean verify` must be green before pushing. All of these fail the build:

- **Checkstyle** (`checkstyle.xml`): `violationSeverity=warning`, test sources included.
- **PMD** and **CPD** (copy-paste detection).
- **SpotBugs**: `threshold=Medium`, `effort=Max`, exclusions only in `spotbugs-exclude.xml` with a reason each.
- **JaCoCo**: 80% line / 70% branch on the aggregated bundle in the `coverage` module (unit + integration).
- **Enforcer**: Java `[21,26)`, Maven 3.9+, and the per-module `bannedDependencies` above.
- **ArchUnit**: the hexagonal rules in each application's `boot` module.

If coverage falls short, add the missing tests; never lower the threshold. Never suppress a Checkstyle, PMD or
SpotBugs finding to make code fit unless the rule is genuinely wrong for that line, and say why next to the
suppression. `*Application` classes are excluded from coverage and carry the one `HideUtilityClassConstructor`
suppression, because a private constructor breaks Spring's configuration proxying.

CI (`.github/workflows/build.yml`) runs `verify` on every push and pull request, then the SonarCloud analysis
(organization `albertoirurueta`, project `albertoirurueta_irurueta-auth-server`) when the `SONAR_TOKEN` secret is set.
The workflow never deploys anything.

`.github/workflows/docs.yml` (*Documentation*, on every push to `main` and on demand) publishes the documentation to
the `gh-pages` branch, served at `https://albertoirurueta.github.io/irurueta-auth-server/`: the Antora site at the
root, the staged Maven site (`target/staging`: aggregated Javadoc, JaCoCo, Surefire/Failsafe, Checkstyle, PMD,
SpotBugs, JXR) under `/mvn-site/` and the API contracts and their html2 rendering under `/openapi/`. The Antora *Reference* page
links those reports, so a new report or module that should be reachable from the docs needs a row there.
