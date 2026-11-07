# Implementation plan: E-mail OTP, magic links and SMS OTP with one-time-token login (issue #6)

## Task summary

Add the **one-time-token (OTT) methods** to `auth-server`: **e-mail codes**, **e-mail magic links** and **SMS codes**.
Each works as a passwordless **primary** factor and as a **second** factor, on Spring Security's `oneTimeTokenLogin()`,
with pluggable delivery (`JavaMailSender` + Thymeleaf to Mailpit; an `SmsSender` port with logging, Twilio and SNS
adapters). It plugs into the login fragments of #3 and the MFA framework of #4 through their extension points; no shared
file (`SecurityConfig`, `MfaPolicy`, `ApiSecurityConfig`, `AuthorizationJsonMapperFactory`) is edited.

Source: GitHub issue #6
Base branch: main
Flyway range: `V600`–`V699` only.

Choices made (challenge them in review):
- **Verify first, then code.** Task 1 reads the real Spring Security 7.1.2 jars with `javap` (`JdbcOneTimeTokenService`,
  `OneTimeTokenLoginConfigurer`, `OneTimeTokenAuthenticationConverter`, success handlers, the official schema
  `one-time-tokens-schema.sql`: `one_time_tokens(token_value varchar(36) pk, username, expires_at)`) before anything relies
  on them, and records the facts in "Current code state".
- **Two token shapes, one login chain.** The **magic link** uses Spring's stock path: `JdbcOneTimeTokenService` issues a
  UUID (the `token_value` primary key), the link opens `GET /login/ott/confirm?token=…`, a page whose button POSTs the token
  to `/login/ott` (so a link scanner's GET never consumes it). The **numeric code** cannot use the UUID column: six digits
  collide across users in a table keyed by token value alone. A code is therefore stored in our own table `ott_codes`
  (hash of the code, username, channel, purpose, a *binding id* held in the requesting browser's session, attempt counter,
  expiry) and checked by our own `AuthenticationProvider` against the binding of the current session, so a code only works in
  the browser that asked for it. Task 1 verified the stock service cannot take a custom token value (always `UUID.randomUUID()`), so the decision stands.
- **Factors and `amr` (registered in #4's framework, no edit of it).** Four `AuthenticationFactor` beans, because one
  authority cannot carry two strengths (the registry fails at startup on two factors with the same authority):
  `FACTOR_OTT` (Spring's constant, `PRIMARY`, `amr` `otp`, e-mail code or link as sign-in), `FACTOR_OTT_SMS` (`PRIMARY`,
  `sms`), `FACTOR_OTT_EMAIL_2FA` (`SECOND`, `otp`) and `FACTOR_OTT_SMS_2FA` (`SECOND`, `sms`). TOTP already reports `otp`
  (`FACTOR_TOTP`): Task 12 checks that `FactorTimeline`/`MfaClaimsContributor` list a repeated value once and still add
  `mfa`.
- **Second factor = our own filter, like TOTP.** `oneTimeTokenLogin()` serves the primary sign-in. The second factor
  posts to `/login/second-factor/ott` and is verified by a provider (lockout, events and `FactorGrantor` through the
  existing use cases), exactly the structure of `api.web.totp`. A magic link used as a second factor must be confirmed in the
  session that already holds the primary factor (it is refused in any other browser).
- **Enrolment query.** A user with a verified phone requires MFA (a `SecondFactorEnrolmentQuery` bean,
  `HasVerifiedPhoneUseCase`); the e-mail second factor needs no enrolment (the account's verified address is used), so by
  itself it does not make MFA required.
- **Enumeration safety.** `POST /ott/generate` always answers the same response and takes the same time path whether the
  identifier exists, is disabled or is unverified; nothing is sent in the unhappy cases. Phone enrolment responds
  identically for a number already taken.
- **Rate limits with Bucket4j + Caffeine**, on the pattern of `account.AccountRateLimiter`: per identifier and per client
  address for generation and verification; for SMS also a country allow-list and a cost cap (a per-window and a per-day budget
  kept in the database through `SmsCostLedgerRepository`, so a restart cannot reset it).
- **New module `infrastructure/sms`** (`auth-server-infrastructure-sms`): `LoggingSmsSender` (default, dev/test),
  `TwilioSmsSender` (profile `twilio`), `SnsSmsSender` (profile `sns`). Credentials come only from environment variables.
  Provider SDKs are profile-gated beans in this module only; CI never calls a gateway. `/dev/sms-inbox` is `dev`-profile
  only and is added to the `CLAUDE.md` list of the narrow "demo-only code in `src/main`" exceptions with the reason (the
  end-to-end tests run the packaged jar).
- **Phone numbers** are normalised to E.164 with Google libphonenumber inside the adapter that needs it; the domain type
  `PhoneNumber` only validates the E.164 shape.

Open clarifications: none

## Acceptance criteria coverage

| # | Criterion | Covered by tasks |
|---|---|---|
| 1 | "All scope items are implemented and tested. `./mvnw verify` green, and the tags are listed in the PR." | Task 2 – Task 19 |
| 2 | derived: `oneTimeTokenLogin()` runs `/ott/generate` → `JdbcOneTimeTokenService` → success handler → `/login/ott` with a configured TTL | Task 1, Task 4, Task 11, Task 12 |
| 3 | derived: the numeric code is bound to the requesting browser and the magic link lands on a POST confirm page | Task 2, Task 6, Task 9, Task 12, Task 14 |
| 4 | derived: e-mail is delivered through `JavaMailSender` and Thymeleaf templates, read from Mailpit in tests | Task 7, Task 17 |
| 5 | derived: phone enrolment and verification (`user_phones`, E.164) and the `SmsSender` adapters (logging, Twilio, SNS) with `/dev/sms-inbox` | Task 3, Task 5, Task 8, Task 10, Task 15 |
| 6 | derived: enumeration-safe responses, Bucket4j limits per identifier and IP, country allow-list, SMS cost cap, token clean-up | Task 6, Task 9, Task 11, Task 13 |
| 7 | derived: OTT factors register in the MFA policy (`amr` `otp` / `sms`) as primary and second factor, with the login fragment and the "enter the code" page | Task 12, Task 14, Task 16, Task 17 |
| 8 | derived: Flyway range, tags, API contracts and architecture rules are checked by the drift and ArchUnit tests | Task 4, Task 11, Task 18, Task 19 |

## Current code state

- Placeholder only: `…api.web.ott/package-info.java` (`auth-server/api/web`). There is no `ott`/`sms` package in `domain`,
  `application` or `infrastructure/persistence`, and nothing references `oneTimeToken` yet.
- Templates to copy: `api/web/totp/` (`TotpFactor` registers an `AuthenticationFactor` bean; `TotpConfiguration` builds the
  provider and filter and returns a `LoginChainCustomizer` (`@Order(1)`; passkeys use `@Order(2)`, so OTT takes `@Order(3)`);
  `TotpChainCustomizer` permits paths and adds filters before `AuthorizationFilter`; `TotpSecondFactorFragment` is a
  `SecondFactorFragment`), and `api/web/passkeys` (primary factor, `LoginMethodFragment`, `AuthorizationJacksonModuleContributor`).
- Extension points: `api.web.login.LoginChainCustomizer`, `LoginMethodFragment` (`templateName/fragmentName/order/reference`),
  `api.web.mfa.SecondFactorFragment`, `application.mfa.SecondFactorEnrolmentQuery`, `domain.mfa.AuthenticationFactor` /
  `FactorStrength`, `MfaPolicy`, `FactorGrantor`, `SecondFactorUserResolver`, `MfaClaimsContributor` (writes `amr`, line ~66,
  adds `mfa` for two distinct factors), `FactorTimeline`, `StepUpGuard`, `CheckSecondFactorLockoutUseCase`,
  `RegisterSecondFactorFailureUseCase`, `ResetSecondFactorFailuresUseCase`, `RecordSecurityEventUseCase`.
- Mail: `infrastructure/mail` has `SmtpAccountMailer` (port `domain.account.AccountMailer`), `MailProperties` (from, base-url,
  locale), `MailConfiguration`, `mail/account-mail.properties`; plain-text only, no Thymeleaf mail templates yet. Mailpit
  runs from `compose.yaml` (SMTP 1025, API/UI 8025); `spring.mail.host/port` are in `application.yml`.
- Rate limiting: `api.web.account.AccountRateLimiter` + `AccountRateLimitProperties` (Bucket4j `bucket4j_jdk17-core`,
  Caffeine, `ClockTimeMeter`) and `authserver.account.rate-limit.*` in `application.yml`; both libraries are already in
  `api/web/pom.xml`.
- Persistence: `auth-server/infrastructure/persistence/src/main/resources/db/migration`, latest `V500`; `users(id uuid,
  username varchar(100) unique, enabled, …)`; hexagonal rules and `bannedDependencies` per module.
- Contracts: `apis/auth-server/rest-server/auth-server-api-v1.yaml` (JSON) and `apis/auth-server/web-pages/auth-server-pages-v1.yaml`
  (HTML pages, springdoc group `pages` in `OpenApiConfig`); framework-owned and exempt: Spring Security filter endpoints
  (`/ott/generate` and `POST /login/ott` are the framework's). Pages we render ourselves need a contract entry.
- Spring Security 7.1.2 OTT classes seen in the jars (to verify in Task 1): `spring-security-core` has
  `org.springframework.security.authentication.ott.*` (`JdbcOneTimeTokenService`, `OneTimeTokenService`,
  `OneTimeTokenAuthenticationProvider`, `DefaultOneTimeToken`) and the schema `core/ott/jdbc/one-time-tokens-schema.sql`;
  `spring-security-web` has `…web.authentication.ott.*` (`GenerateOneTimeTokenFilter`, `GenerateOneTimeTokenRequestResolver`,
  `DefaultGenerateOneTimeTokenRequestResolver`, `OneTimeTokenGenerationSuccessHandler`, `OneTimeTokenAuthenticationFilter`,
  `OneTimeTokenAuthenticationConverter`, `DefaultOneTimeTokenSubmitPageGeneratingFilter`); `spring-security-config` has
  `OneTimeTokenLoginConfigurer`; `FactorGrantedAuthority.OTT_AUTHORITY` is `FACTOR_OTT`.
- **Verified Spring Security 7.1.2 OTT facts (Task 1.1, `javap -p -c -constants`)**:
  - `JdbcOneTimeTokenService implements OneTimeTokenService, DisposableBean, InitializingBean` (final): constructor
    `(JdbcOperations)`; `setCleanupCron(String)` (default `@hourly`, runs its own `ThreadPoolTaskScheduler`),
    `setClock(Clock)`, `cleanupExpiredTokens()` public (`DELETE ... WHERE expires_at < ?`). Table `one_time_tokens`
    (`token_value varchar(36)` pk, `username varchar_ignorecase(50)`, `expires_at timestamp`; SQL is hard-coded, table and columns
    not configurable). **`generate` always uses `UUID.randomUUID()`**: the token value cannot be customised; a different value
    needs our own `OneTimeTokenService` (interface `generate(GenerateOneTimeTokenRequest)`, `consume(OneTimeTokenAuthenticationToken)`).
    `GenerateOneTimeTokenRequest(username[, Duration expiresIn])`; `DefaultOneTimeToken(tokenValue, username, expiresAt)`.
  - `OneTimeTokenLoginConfigurer`: `tokenGeneratingUrl(String)` (default `/ott/generate`), `tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler)`
    (`handle(request, response, OneTimeToken)`), `generateRequestResolver(GenerateOneTimeTokenRequestResolver)` (`resolve(request)`;
    the default resolver has `setExpiresIn(Duration)`), `tokenService(OneTimeTokenService)`, `authenticationConverter(AuthenticationConverter)`,
    `authenticationProvider(AuthenticationProvider)`, `defaultSubmitPageUrl(String)`, `showDefaultSubmitPage(boolean)`, `loginPage(String)`,
    `loginProcessingUrl(String)` (default `/login/ott`), `authenticationSuccessHandler/FailureHandler`.
  - `OneTimeTokenAuthenticationConverter` reads the request parameter **`token`**; the filter `OneTimeTokenAuthenticationFilter`
    (final, extends `AbstractAuthenticationProcessingFilter`, `POST /login/ott`).
  - `OneTimeTokenAuthenticationProvider(OneTimeTokenService, UserDetailsService)` builds `OneTimeTokenAuthentication` from the user's
    authorities plus `FactorGrantedAuthority.fromAuthority("FACTOR_OTT")`. The merge with the factors already in the session lives in
    `AbstractAuthenticationProcessingFilter` (`mfaEnabled`/`shouldPerformMfa`), the base class of the OTT and WebAuthn filters, so
    OTT merges exactly as the passkey does (same user name after a password gives `FACTOR_PASSWORD` + `FACTOR_OTT`).
  - Dependencies pinned in the root pom (Task 1.2): `com.googlecode.libphonenumber:libphonenumber` 9.0.43 (the plan's
    `com.google.i18n.phonenumbers` is the Java package, not the groupId), `com.twilio.sdk:twilio` 13.2.0 (MIT), AWS SDK v2 BOM 2.57.11
    (Apache 2.0; `software.amazon.awssdk:sns` is declared by Task 8). No `bannedDependencies` rule bans third-party jars (they only
    ban `auth-server-api-*`/`infrastructure-*`, Spring from `domain`, Spring Security from `application`), so nothing is widened.
- Tests: `boot` holds `SecurityConfigIT` and `OpenApiDriftIT`; `PasswordAuthenticationIT` asserts the login page contents (it
  will change); `e2e-tests` drives the packaged jars with Playwright (`RunningAuthServer`, `PasskeyEndToEndIT`).
- Archived precedents: `.archive/implementation_plan_5.md` (a factor, fragments and its own Flyway range),
  `implementation_plan_4.md` (the factor framework, TOTP), `implementation_plan_3.md` (login fragments).
- Stack: Java 21–25, Maven wrapper, Spring Boot 4.1 / Spring Security 7.1.2, hexagonal reactor with `bannedDependencies` in each
  module and `HexagonalArchitectureTest`; project type `java-springboot`.

## Implementation steps

### Group 1 — Verify the framework and add dependencies (Parallelizable: yes, one task)

- [x] Task 1. Verify the OTT classes and add dependencies _(java-springboot)_
  - [x] Task 1.1. With `javap -p` on the `spring-security-core/web/config` 7.1.2 jars, record in "Current code state" the exact
        signatures: `JdbcOneTimeTokenService` (constructor, `setCleanupCron`, `cleanupExpiredTokens`, table/column names,
        whether the token value can be customised), `OneTimeTokenLoginConfigurer` methods (`tokenGenerationSuccessHandler`,
        `generateRequestResolver`, `tokenService`, `authenticationConverter`, `defaultSubmitPageUrl`, `tokenGeneratingUrl`,
        `loginProcessingUrl`), the converter's parameter name, and whether the authentication filter merges the existing
        factor authorities as the WebAuthn one does. Adjust the "two token shapes" decision above if the facts disagree.
  - [x] Task 1.2. Add `com.googlecode.libphonenumber:libphonenumber` and the Twilio and AWS SDK v2 (`software.amazon.awssdk:sns`)
        dependencies, pinned in the root `pom.xml` `dependencyManagement` (SNS through the AWS BOM import) and declared only in
        the new `auth-server/infrastructure/sms` module (Task 8); libphonenumber also in `infrastructure/sms` only.
  - [x] Task 1.3. Check each module's `bannedDependencies` list and the license of each new jar; widen an allow-list only where the
        rule requires it, never weaken the hexagonal rules.
    - Done: facts recorded in "Current code state"; `pom.xml` only (no tests apply, `validate` green); no rule widened; licenses
      MIT (Twilio) and Apache 2.0 (libphonenumber, AWS SDK); license-header generation skipped (no source file touched).

### Group 2 — Domain and database (Parallelizable: yes, three independent files sets)

- [x] Task 2. OTT domain in `…domain.ott` _(java-springboot)_
  - [x] Task 2.1. Records and enums: `OttChannel` (`EMAIL`, `SMS`), `OttKind` (`CODE`, `LINK`), `OttPurpose` (`LOGIN`, `SECOND_FACTOR`),
        `OneTimeCode` (id, username, channel, purpose, `codeHash`, `bindingId`, `attempts`, `expiresAt`, `createdAt`), validated in
        compact constructors with `domain.Preconditions`.
  - [x] Task 2.2. Ports: `OneTimeCodeRepository` (`save`, `findActive(bindingId, username)`, `incrementAttempts`, `consume`,
        `deleteExpired(Instant)`, never returns `null`), `OneTimeCodeGenerator` (numeric code of N digits), `OneTimeCodeHasher`,
        `OttDelivery` (sends a code or a link to a destination by channel).
  - [x] Task 2.3. Pure policy `OttPolicy` (TTL per kind, code length, attempt limit) as a plain class, a bean in `application`.
  - [x] Task 2.4. Unit tests for every type (`OneTimeCodeTest`, `OttPolicyTest`, …), JUnit assertions only.
- [x] Task 3. Phone and SMS domain in `…domain.sms` _(java-springboot)_
  - [x] Task 3.1. `PhoneNumber` record (E.164 shape `^\+[1-9]\d{6,14}$`, a `countryCode`-independent value object), `UserPhone`
        (userId, `PhoneNumber`, `verifiedAt`), `SmsMessage`.
  - [x] Task 3.2. Ports: `SmsSender` (`send(PhoneNumber, String)`, throws `SmsDeliveryException`, never leaks gateway types),
        `UserPhoneRepository`, `PhoneVerificationRepository` (pending verification, hashed), `SmsCostLedgerRepository`
        (`recordAndGetSpend(window)`), `PhoneNormalizer` (E.164 from user input and a default region).
  - [x] Task 3.3. `SmsCostPolicy` (allowed countries, per-window and per-day caps, cost per message by country) as a pure class;
        unit tests.
- [x] Task 4. Flyway migrations in `V600`–`V699` _(java-springboot)_
  - [x] Task 4.1. `V600__one_time_tokens.sql`: the official `one_time_tokens` schema adapted to PostgreSQL (`timestamp with time zone`,
        `username varchar(100)`), plus an index on `expires_at`, wrapped in `-- tag::ott-schema[]` / `-- end::ott-schema[]`.
  - [x] Task 4.2. `V610__ott_codes.sql`: `ott_codes` (uuid id, username, channel, purpose, `code_hash`, `binding_id`, `attempts`,
        `expires_at`, `created_at`), index on `(binding_id, username)` and on `expires_at`.
  - [x] Task 4.3. `V620__user_phones.sql`: `user_phones` (user_id uuid FK `users` on delete cascade, `phone_e164` unique, `verified_at`,
        pending verification hash and expiry) and `V630__sms_cost_ledger.sql` (`sms_cost_ledger`: sent_at, country, cost_micros).

> Group 2 done: domain `ott` (3 enums, `OneTimeCode`, `OttPolicy`, 4 ports, `OttDeliveryException`) and `sms` (`PhoneNumber`, `UserPhone`,
> `PhoneVerification`, `SmsMessage`, 5 ports, `SmsCostPolicy`, `SmsDeliveryException`) with 100% line coverage (one branch of
> `SmsCostPolicy` uncovered), no new Checkstyle/PMD/SpotBugs findings; migrations V600-V630 applied on postgres:18.

### Group 3 — Adapters and application use cases (Parallelizable: yes; each task owns distinct modules and packages)

- [x] Task 5. Persistence adapters in `…infrastructure.persistence.ott` and `.sms` _(java-springboot)_
  - [x] Task 5.1. `JdbcOneTimeCodeRepository`, `JdbcUserPhoneRepository`, `JdbcPhoneVerificationRepository`,
        `JdbcSmsCostLedgerRepository`, each with a `RowMapper` class where rows are mapped; no transactions of their own.
  - [x] Task 5.2. `OneTimeTokenServiceConfiguration` exposing a `JdbcOneTimeTokenService` bean over `JdbcOperations`.
  - [x] Task 5.3. A `@PostgresIT` per repository (`*IT`), and `*Test` for the mappers.
- [x] Task 6. OTT use cases in `…application.ott` _(java-springboot)_
  - [x] Task 6.1. `@Transactional` use cases: `RequestOneTimeCodeUseCase` (enumeration-safe: nothing happens for an unknown, disabled
        or unverified identifier but the same result is returned), `VerifyOneTimeCodeUseCase` (binding check, attempt counter,
        constant-time hash compare, lockout and security events for the second factor), `CleanupOttUseCase` (expired codes and
        Spring's `one_time_tokens`), `ResolveOttDestinationUseCase`.
  - [x] Task 6.2. A `@Configuration` declaring `OttPolicy`, `OneTimeCodeGenerator`, `OneTimeCodeHasher` as beans; a use case never
        `new`s a collaborator.
  - [x] Task 6.3. `*Test` per use case with `@ExtendWith(MockitoExtension.class)`, `@InjectMocks`, `ArgumentCaptor.captor()`.
- [x] Task 7. E-mail delivery in `infrastructure/mail` _(java-springboot)_
  - [x] Task 7.1. `ThymeleafOttMailer` implementing `OttDelivery` for `EMAIL`: `JavaMailSender` + a `TemplateEngine` over
        `mail/ott-code.html|txt` and `mail/ott-link.html|txt` (locale from `MailProperties`, never the platform's), messages in
        `mail/ott-mail.properties`; the magic link points at the confirm page, never at an endpoint that consumes the token.
        Delivery failures become a domain `OttDeliveryException` carrying neither the address nor the token.
  - [x] Task 7.2. Add `spring-boot-starter-thymeleaf` to the module's pom (check its `bannedDependencies`), wire the bean in
        `MailConfiguration`, add `ThymeleafOttMailerTest` with a mock `JavaMailSender` and a captor for the `MimeMessage`.
- [x] Task 8. SMS adapters in the new module `auth-server/infrastructure/sms` _(java-springboot)_
  - [x] Task 8.1. Module pom (`auth-server-infrastructure-sms`, depends on `domain` and `application`, enforcer banning sibling
        adapters and `api/*`), registration in `auth-server/infrastructure/pom.xml`, `boot/pom.xml`, the root `dependencyManagement`,
        `coverage` aggregate and a scan in `docs/antora.yml`.
  - [x] Task 8.2. `LoggingSmsSender` (default; writes to a bounded in-memory outbox that only the `dev` inbox exposes),
        `TwilioSmsSender` (`@Profile("twilio")`, `TwilioProperties` from `AUTHSERVER_SMS_TWILIO_*`), `SnsSmsSender`
        (`@Profile("sns")`, AWS SDK v2 `SnsClient`, region and credentials from the default provider chain); every gateway failure
        becomes `SmsDeliveryException`.
  - [x] Task 8.3. `LibPhoneNumberNormalizer` implementing `PhoneNormalizer` (default region from settings, rejects invalid numbers).
  - [x] Task 8.4. Unit tests with mocks: Twilio and SNS success and failure, normalizer cases (national, `+`, garbage), logging sender.
- [x] Task 9. SMS and phone use cases in `…application.sms` _(java-springboot)_
  - [x] Task 9.1. `StartPhoneEnrolmentUseCase` (normalise, cost policy check, send a verification code), `ConfirmPhoneUseCase`,
        `RemovePhoneUseCase`, `SendSmsOneTimeCodeUseCase` (country allow-list + cost cap through `SmsCostPolicy` and
        `SmsCostLedgerRepository`), `HasVerifiedPhoneUseCase` and a `SecondFactorEnrolmentQuery` bean over it. Responses for a number
        that already belongs to another user are identical to the success case.
  - [x] Task 9.2. `OttProperties` / `SmsProperties` `@ConfigurationProperties` records in `application` (`authserver.ott.*`,
        `authserver.sms.*`, validated, never `@Value`), tests with `@ExtendWith(MockitoExtension.class)`.

> Group 3 done: persistence (`ott`, `sms` JDBC repositories, `JdbcExpiredLinkTokenPurger`, `JdbcOneTimeTokenService` bean), application (`ott`, `sms` use cases,
> properties, policy beans), mail (`ThymeleafOttMailer`), new module `infrastructure/sms` (logging/Twilio/SNS senders, libphonenumber normaliser and country
> resolver). Full `verify` (all modules but e2e-tests, JaCoCo gate included) green, 0 new Checkstyle/PMD/SpotBugs findings. New ports implemented here:
> `application.ott.ExpiredLinkTokenPurger` and `application.sms.PhoneCountryResolver`. ArchUnit rule for `application` now also allows `org.slf4j..` (for `@Slf4j`).


### Group 4 — API contracts, then web wiring (Parallelizable: no — Task 11 produces the generated interfaces that Tasks 12–14 implement)

- [x] Task 10. Contracts first _(java-springboot)_
  - [x] Task 10.1. `auth-server-api-v1.yaml`: `GET/PUT/DELETE /api/account/phone` and `POST /api/account/phone/verify`
        (every operation, parameter and schema described and constrained; `DELETE` calls `StepUpGuard`), then regenerate with
        `./mvnw -pl auth-server/api/web -am generate-sources`.
  - [x] Task 10.2. `auth-server-pages-v1.yaml`: `GET /login/ott/confirm` (magic-link confirm page), `GET /login/ott` (enter the code)
        and `GET /dev/sms-inbox` (dev profile only); add the paths to the `pages` springdoc group in `OpenApiConfig`; update
        `apis/README.md`.
- [x] Task 11. Limits and wiring in `…api.web.ott` _(java-springboot)_
  - [x] Task 11.1. `OttRateLimiter` + `OttRateLimitProperties` on the `AccountRateLimiter` pattern (Bucket4j + Caffeine, per
        identifier and per IP, generation and verification buckets, injected `Clock`); `OttRateLimitExceededException` and
        a problem-details handler through `ProblemJsonExceptionHandler`.
  - [x] Task 11.2. `OttGenerateRequestResolver` (`GenerateOneTimeTokenRequestResolver` setting the TTL from `OttPolicy`),
        `OttGenerationSuccessHandler` (`OneTimeTokenGenerationSuccessHandler`: delivers by channel through `OttDelivery`,
        always redirects to the same "check your inbox" response), `OttChainCustomizer` (`LoginChainCustomizer`, `@Order(3)`,
        `http.oneTimeTokenLogin(...)` with the beans above, permits `/ott/generate`, `/login/ott/**`, adds the second-factor filter).
  - [x] Task 11.3. `OttConfiguration` returning the customizer (filters built there, never beans, as `TotpConfiguration`).
  - [x] Task 11.4. `OttFactors` (`@Configuration`) with the four `AuthenticationFactor` beans and a `*Test` per factor and per
        configuration class.
- [x] Task 12. Authentication providers and filters _(java-springboot)_
  - [x] Task 12.1. `OttCodeAuthenticationProvider` (numeric code bound to the session, adds the channel factor with `FactorGrantor`),
        `OttSecondFactorAuthenticationProvider` / `OttSecondFactorFilter` (`POST /login/second-factor/ott`, success changes the
        session id and renews CSRF with the chain's `SessionAuthenticationStrategy`, resumes the saved request).
  - [x] Task 12.2. Per-channel authority: a decorator over the stock provider replaces `FACTOR_OTT` with `FACTOR_OTT_SMS` for the SMS
        channel; magic-link second-factor confirmation refused outside the primary-factor session.
  - [x] Task 12.3. Check in a test that `FactorTimeline`/`MfaClaimsContributor` list a duplicate `otp` once and still add `mfa`;
        change `FactorTimeline` only if it does not.
  - [x] Task 12.4. Unit tests per class (`*Test`), including lockout counting and security events.
- [x] Task 13. Controllers over the generated interfaces _(java-springboot)_
  - [x] Task 13.1. `PhoneController` (JSON, uses the use cases of Task 9, `StepUpGuard` on removal), `PhoneDtoMapper`.
  - [x] Task 13.2. `OttPagesController` (confirm and enter-code pages through `PageRenderer`), `DevSmsInboxController`
        (`@Profile("dev")`, reads the logging sender's outbox), each with a `*Test`.
  - [x] Task 13.3. `OttCleanupJob` (`@Component` with `@Scheduled`, calls `CleanupOttUseCase`; scheduling is not re-enabled).

> Group 4 done. Contracts: `auth-server-api-v1.yaml` (+ `GET/PUT/DELETE /api/account/phone`, `POST /api/account/phone/verify`, tags
> `phone-api-contract` / `phone-schemas`) and `auth-server-pages-v1.yaml` (+ `/login/ott`, `/login/ott/confirm`, `/dev/sms-inbox`, tags
> `ott-pages-api` / `sms-dev-inbox-page-api`), `OpenApiConfig` pages group, `apis/README.md`. Code in `…api.web.ott` (34 classes, tags
> `ott-generate-resolver`, `ott-rate-limit`, `ott-factors`, `ott-chain`, `ott-chain-customizer`) plus the shared `api.web.ratelimit.FixedWindowBuckets`
> (extracted so `AccountRateLimiter` and `OttRateLimiter` do not duplicate it; CPD) and, outside the plan text, `domain.sms.SmsInbox` /
> `SmsInboxEntry` (port the dev inbox reads; `SmsOutbox` implements it, because `api/*` cannot see `infrastructure/sms`) and
> `application.sms.FindUserPhoneUseCase` (for `GET /api/account/phone`). Unit coverage of `api.web.ott`: 100 % line / 99.4 % branch;
> `./mvnw -B clean verify -pl '!e2e-tests'` green (0 Checkstyle/PMD/CPD violations, SpotBugs clean, ArchUnit, `OpenApiDriftIT`, JaCoCo gate).
> Departures: (1) Task 12.2 has no decorator over Spring's provider: its link token carries no channel and no purpose, so
> `OttLinkAuthenticationProvider` consumes the token itself and reads the purpose from the stored user name (`LinkTokenUsername`, a control-character
> marker for a second-factor link); links are only sent by e-mail, so the SMS authority comes from the code provider. (2) Minimal templates
> `ott-code.html`, `ott-confirm.html`, `dev-sms-inbox.html` and their messages exist for Group 5 to refine. (3) `OpenApiDriftIT` leaves the `/dev/` pages out
> of the comparison; `spotbugs-exclude.xml` got an `OttSecondFactorToken` entry (as `TotpAuthenticationToken`) and two narrow
> `RV_RETURN_VALUE_IGNORED_NO_SIDE_EFFECT` entries that the detector began to raise for two untouched customizers once `OneTimeTokenLoginConfigurer` was referenced.

### Group 5 — Templates and messages (Parallelizable: yes)

- [x] Task 14. Login fragment, pages and second-factor fragment _(java-springboot)_
  - [x] Task 14.1. `templates/login-ott.html` (`LoginMethodFragment` `OttLoginMethodFragment`, tagged `ott-login-fragment`):
        identifier field and the choice of code or link, posting to `/ott/generate`.
  - [x] Task 14.2. `templates/ott-code.html` (enter the code, posting to `/login/ott` or `/login/second-factor/ott`),
        `templates/ott-confirm.html` (button that POSTs the token), `OttSecondFactorFragment` + `templates/ott-second-factor.html`.
  - [x] Task 14.3. `templates/dev-sms-inbox.html`; all texts in `messages.properties` (never hard-coded), WCAG basics (labels,
        `aria-live` for errors).
- [x] Task 15. Account area for the phone _(java-springboot)_
  - [x] Task 15.1. A small section or page to enrol, verify and remove a phone, reusing the account layout fragment; texts in
        `messages.properties`; keep it inside the pages contract of Task 10.

> Group 5 done. Task 14: `OttLoginMethodFragment` (`login-ott.html`, tag `ott-login-fragment`, order 300), `OttSecondFactorFragment`
> (`ott-second-factor.html`, offers e-mail code/link unless e-mail signed the user in, SMS only with a verified phone and not signed in by SMS),
> refined `ott-code`, `ott-confirm`, `dev-sms-inbox` (table) and messages (`ott.*`, `devSmsInbox.*`). Task 15: new page `/account/phone`
> (`account-phone.html`, `PhonePageController`, `PhonePageChainCustomizer` @Order(4) behind the MFA policy, `PhoneSessionStepUp`), with
> session form posts `POST /account/phone`, `/account/phone/verify`, `/account/phone/remove` (303 back with `status`) declared in the pages
> contract, `OpenApiConfig`, `apis/README.md`. Tests: unit tests per new class and `OttPagesIT`.

### Group 6 — Configuration and shared edits (Parallelizable: no — shared files, one task)

- [x] Task 16. Settings and shared files _(java-springboot)_
  - [x] Task 16.1. `application.yml`: `authserver.ott.*` (code-length, code-ttl, link-ttl, max-attempts) and `authserver.sms.*`
        (default-region, allowed-countries, caps, `sender` profile hints), tagged `ott-config` / `sms-config`; profile files for
        `twilio` and `sns` that take credentials from the environment only.
  - [x] Task 16.2. Update `PasswordAuthenticationIT` and `SecurityConfigIT` expectations for the new fragment; `CLAUDE.md` gets an
        OTT section, the `V600` range, the new module and the dev-inbox exception.
  - [x] Task 16.3. Delete the placeholder `package-info.java` text of `…ott` and add real package docs to every new package.

> Group 6 done. `application.yml` (`ott-config`, `sms-config`), `application-twilio.yml`, `application-sns.yml` (env var names only), `api.web.ott` package docs, two new tests in `PasswordAuthenticationIT`, CLAUDE.md OTT section and shared lists. `./mvnw -B clean verify -pl '!e2e-tests'` green.

### Group 7 — Integration and end-to-end tests (Parallelizable: yes, separate test classes)

- [x] Task 17. Integration tests in `boot` _(java-springboot)_
  - [x] Task 17.1. `OttEmailCodeIT` / `OttMagicLinkIT`: sign in with a code and a link as primary and as second factor, reading the mail
        through the Mailpit HTTP API (Testcontainers `axllent/mailpit` added to `test-support`).
  - [x] Task 17.2. `OttSmsIT`: SMS login and second factor through the logging sender; `OttSmsAdaptersIT` is not needed (Twilio and SNS are
        unit-tested with mocks).
  - [x] Task 17.3. `OttRateLimitIT` and `OttEnumerationIT`: identical status, body and delivery for known and unknown identifiers; limits per
        identifier and per IP; country allow-list and cost cap.
  - [x] Task 17.4. Delegate each run to the `iru-gate-runner` agent so test output stays out of the main context.
- [x] Task 18. End-to-end test _(java-springboot)_
  - [x] Task 18.1. `OttEndToEndIT` in `e2e-tests`: Playwright signs in with an e-mail code from Mailpit and with a magic link (scanner GET does not
        consume it), and enrols a phone through the dev inbox.

> Group 7 done. Task 17: `test-support` gained `Mailpit` (image pinned `axllent/mailpit:v1.29.0`), `MailpitClient` and `MailpitTestConfiguration`; in `boot`
> `AbstractOttFlow` plus `OttEmailCodeIT` (5), `OttMagicLinkIT` (5), `OttSmsIT` (4), `OttEnumerationIT` (3), `OttRateLimitIT` (5), `OttSmsLimitsIT` (3, country
> allow-list and cost cap). Task 18: `OttEndToEndIT` (3) in `e2e-tests`. `./mvnw -B clean verify` green: 0 Checkstyle/PMD/CPD/SpotBugs findings, aggregate
> JaCoCo 99.2 % line / 98.1 % branch, license headers already compliant. **Production bug found and fixed**: `OttChainCustomizer` added the rate-limit
> filter before `UsernamePasswordAuthenticationFilter`, but Spring's `GenerateOneTimeTokenFilter` sits earlier and answers `POST /ott/generate` itself, so
> generation was never limited; it is now added before `GenerateOneTimeTokenFilter` (`OttChainCustomizerTest` updated). Observations left as designed: a verified
> phone makes MFA required, so an SMS sign-in alone (and the session right after enrolling a phone) is asked for a second factor.

### Group 8 — Documentation and final gates (Parallelizable: no — depends on everything above)

- [x] Task 19. Docs and the full build
  - [x] Task 19.1. Run `/iru-update-docs` and add the new tags to the PR description: `ott-schema`, `ott-config`, `sms-config`,
        `ott-login-fragment`, `ott-generate-resolver`, `ott-rate-limit`, `ott-factors`, `sms-sender`, `sms-adapters`; no existing tag renamed or removed.
  - [x] Task 19.2. Run `./mvnw -B clean verify` (Checkstyle, PMD/CPD, SpotBugs, JaCoCo 80/70, Enforcer, ArchUnit, drift) through `iru-gate-runner`;
        run `/iru-check-license` and `/iru-check-security` (no secret or key committed; Twilio/SNS credentials appear only as environment names).
    - Group 8 note: docs page `one-time-tokens.adoc` added (nav, data-model V600-V630, reference updated); tags `sms-sender` (SmsSender.java) and `sms-adapters` (SmsAdapterConfiguration.java) added; no pre-existing tag removed/renamed vs main.
      Tags for the PR description: `ott-schema`, `ott-config`, `sms-config`, `ott-login-fragment`, `ott-generate-resolver`, `ott-rate-limit`, `ott-factors`, `sms-sender`, `sms-adapters` (also present: `ott-codes-schema`, `sms-phones-schema`, `sms-cost-ledger-schema`, `ott-rate-limit-config`, `ott-token-service`, `ott-chain`, `ott-chain-customizer`, `ott-resolver-bean`, `ott-second-factor-fragment`, `ott-mailer`).
      `./mvnw -B clean verify` green: 1920 tests, 0 Checkstyle/PMD/CPD/SpotBugs issues, JaCoCo aggregate 99.22% line / 98.13% branch, ArchUnit and drift pass. License check: 6 missing headers fixed. Security: no secret in tracked files.
