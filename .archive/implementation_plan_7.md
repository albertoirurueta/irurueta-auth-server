# Implementation plan: Social login / identity brokering, X.509 client certificates and device authorization grant (issue #7)

## Task summary

Add three login capabilities to `auth-server`, each registered through the existing extension points (no edit of
`SecurityConfig`, `MfaPolicy`, `ApiSecurityConfig`, `AuthorizationJsonMapperFactory`):

1. **Identity brokering**: `oauth2Login()` in the login chain with Google, Microsoft Entra ID (multi-tenant issuer
   validation), Apple (`client_secret` JWT signed with #2's `JwtEncoder`) and GitHub (OAuth2, not OIDC), the
   `login-social.html` fragment, **account linking and JIT provisioning** (`FederatedIdentityService` behind the
   `OidcUserService` / `OAuth2UserService`, `federated_identities` table, unlink from the account API), and claims
   (`sub` = local user id, `amr` with `fed` plus upstream `amr`, `idp` claim, per-provider MFA trust with step-up).
2. **X.509 client certificates**: `x509()` with a custom `X509PrincipalExtractor`, certificate-to-user mapping, `amr`
   `sc` / `hwk`, TLS client auth on a dedicated port **and** a forwarded certificate header, runtime-generated dev/test
   certificates (never committed).
3. **Device authorization grant** (RFC 8628): enabled in the server, custom `/oauth2/device_verification` page,
   `device-client` registration, polling CLI (a main class in `service-client`).
4. **Push approval**: design notes only, in the PR description. No code.

Source: GitHub issue #7
Base branch: main
Flyway range: `V700`-`V799` only (`V700` `federated_identities`, `V710` `x509_certificates`).
Feature packages: `social`, `x509`, `implicit` (device grant lives in `implicit`, whose placeholder says so) in every layer.

Choices made (challenge them in review):
- **Verify first, then code.** Task 1 reads the real Spring Security 7.1 / Spring Authorization Server jars with `javap`
  (`OAuth2LoginConfigurer`, `OidcUserService`, `X509Configurer`, `OAuth2DeviceAuthorizationEndpointConfigurer`,
  `OAuth2DeviceVerificationEndpointConfigurer`, the stored `device_code_*` columns) and records the facts under "Current
  code state" before anything relies on them.
- **Federated factor model.** One `AuthenticationFactor` per kind: `FACTOR_FEDERATED` (`amr` `fed`, `PRIMARY`),
  `FACTOR_X509` (`amr` `sc`, `PRIMARY_STRONG` for a certificate on a smart card/hardware token, else `hwk` is reported only
  when the certificate policy says hardware-bound; default `sc`). A provider marked `trust-mfa: true`
  (`authserver.social.providers.<id>.trust-mfa`) is **not** a different strength: the upstream `amr` is copied to the
  token and the login is accepted as `PRIMARY_STRONG` only when the upstream `amr` contains `mfa`; otherwise it is a
  `PRIMARY` and the normal second-factor/step-up flow applies (recommended: safest default, no new framework concept).
- **Provider trust is configuration, not a table.** `SocialProperties` (validated `@ConfigurationProperties` record) holds
  per-provider client id, secret (env var only), tenant policy and `trust-mfa`; no secret in any committed file.
- **Linking rule.** Link by verified e-mail only when the IdP says `email_verified=true` (GitHub: the verified primary
  e-mail from `/user/emails`); an unverified e-mail never links and never provisions over an existing account; a signed-in
  user may link explicitly. JIT provisioning creates a password-less account.
- **X.509 transport.** Both are implemented behind one `X509PrincipalExtractor` bean: direct TLS client auth on a dedicated
  port (`authserver.x509.port`, off by default) and a forwarded certificate header (`authserver.x509.forwarded-header`, only
  accepted from `authserver.x509.trusted-proxies`). The mapping `x509_certificates` stores the SHA-256 fingerprint and
  subject DN per user.
- **Fake IdP.** WireMock (standalone, `org.wiremock:wiremock-standalone`, test scope in `test-support`/`boot`) over a mock
  OIDC container: runs in-process, no Docker, deterministic in CI.
- **Device CLI placement.** `DeviceFlowCli` is a hand-written main class in `service-client/boot` (the application stays a
  single `boot` module until #8 adds its domain); it uses `RestClient` against the standard endpoints, so no contract is
  generated for it. It is not in `src/test` because the end-to-end test runs the packaged jar; the Javadoc says so.
- **Contracts first.** Every new JSON/HTML endpoint is added to `apis/auth-server/` before its controller
  (`/api/account/identities` list and unlink, `/oauth2/device_verification` page); framework-owned endpoints
  (`/oauth2/authorization/**`, `/login/oauth2/code/**`, `/oauth2/device_authorization`) stay exempt.

Open clarifications: none

## Acceptance criteria coverage

| # | Criterion | Covered by tasks |
|---|---|---|
| 1 | "All scope items are implemented and tested." | Task 2 - Task 22 |
| 2 | "No real IdP secrets or certificates committed." | Task 9, Task 12, Task 16, Task 22 |
| 3 | "`./mvnw verify` green" | Task 22 |
| 4 | "the tags are listed in the PR" | Task 22 |
| 5 | derived: Google/Entra/Apple/GitHub sign in, first login provisions an account, a verified e-mail links to an existing one, an unverified one never does | Task 6, Task 9, Task 15 |
| 6 | derived: tokens carry local `sub`, `amr` with `fed` (+ upstream), `idp`; an untrusted provider triggers second-factor step-up | Task 10, Task 15 |
| 7 | derived: unlinking an identity through `/api/account/identities` under `StepUpGuard` | Task 2, Task 6, Task 11, Task 15 |
| 8 | derived: X.509 sign-in via TLS port and forwarded header, certificate mapped to a user, `amr` `sc`/`hwk` | Task 7, Task 12, Task 16 |
| 9 | derived: device grant end to end (device code, verification page, polling CLI obtains tokens) | Task 13, Task 14, Task 17 |
| 10 | derived: push-approval design notes in the PR | Task 22 |

## Current code state

- Placeholders only: `…api.web.social`, `…api.web.x509`, `…api.web.implicit` (`package-info.java` in `auth-server/api/web`).
  No `social`/`x509`/`implicit` package in `domain`, `application` or `infrastructure/persistence`; nothing references
  `oauth2Login`, `x509(` or `FederatedIdentity`.
- Extension points to use: `api.web.login.LoginChainCustomizer` (`@Order` 0 MFA, 1 TOTP, 2 passkeys, 3 OTT, 4 phone page: social
  takes `@Order(5)`, x509 `@Order(6)`), `LoginMethodFragment`, `api.web.ProtocolChainCustomizer` (`@Order` 0 MFA, 1 step-up:
  device grant takes `@Order(2)`), `api.web.tokens.JwtClaimsContributor` (`MfaClaimsContributor` `@Order(100)` writes `amr`/`acr`/
  `auth_time`; social adds `idp` and `fed`), `domain.mfa.AuthenticationFactor` / `FactorStrength`, `AuthenticationFactorRegistry`,
  `FactorGrantor`, `FactorTimeline`, `StepUpGuard`, `application.mfa.SecondFactorEnrolmentQuery`, `RecordSecurityEventUseCase`.
- `AuthorizationJacksonModuleContributor` (`infrastructure.persistence.clients`) must register the federated principal types
  (`OAuth2User`/`OidcUser` authorities) or a stored social sign-in cannot be read back at the token request.
- `oauth2_authorization` (V100) already has `device_code_*` and `user_code_*` columns; `RegisteredClientMapper` passes any grant
  type through. `DevDataInitializer` seeds dev clients: add `device-client` there (dev-only, per the CLAUDE.md exception).
- `service-client/boot`: `ServiceClientApplication` + `ServiceClientApplicationIT`, no domain yet (#8).
- Test tooling: `test-support` has `@PostgresIT`, Mailpit; `e2e-tests` has Playwright `*EndToEndIT` + `ManagedApp`/`RunningAuthServer`.
  WireMock is not yet a dependency.
- Last Flyway files: `V630`; account/MFA/passkey/OTT tests are the templates (`PasswordAuthenticationIT`, `PasskeyEndToEndIT`, `OttEndToEndIT`).
- Docs: `docs/modules/ROOT/pages/` (new `social-login.adoc`, `x509.adoc`, `device-grant.adoc`), `docs/antora.yml` scans, `apis/README.md`.
- Facts recorded by Task 1 (read with `javap` from the 7.1.2 jars in `~/.m2`; Boot 4.1.2 manages `spring-security.version` 7.1.2; there is no 7.1 specific API difference found below):
  - **Dependency gap**: `auth-server` has no `spring-security-oauth2-client` yet (only the `bff` and `service-client` poms declare `spring-boot-starter-security-oauth2-client`). The jar `spring-security-oauth2-client-7.1.2` is already in `~/.m2`; add `spring-boot-starter-security-oauth2-client` to `auth-server/api/web` (the Jackson mixins of the client types, `OAuth2ClientJacksonModule`, are in the same jar and are what the stored principal needs, see the contributor below). The `OAuth2ClientJacksonModule` / `DefaultOidcUserMixin` / `OAuth2AuthenticationTokenMixin` classes exist in `org.springframework.security.oauth2.client.jackson`.
  - **Configurers live in `spring-security-config`** (not in the authorization-server jar): `org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.{OAuth2AuthorizationServerConfigurer, OAuth2DeviceAuthorizationEndpointConfigurer, OAuth2DeviceVerificationEndpointConfigurer}`.
  - **`OAuth2LoginConfigurer<B>`** (final): `clientRegistrationRepository`, `authorizedClientRepository`, `authorizedClientService`, `loginPage`, `loginProcessingUrl` (default `/login/oauth2/code/*`, filter `OAuth2LoginAuthenticationFilter`), `securityContextRepository`, `oidcSessionRegistry`, and Customizer-based `authorizationEndpoint`, `tokenEndpoint`, `redirectionEndpoint`, `userInfoEndpoint`.
    - `AuthorizationEndpointConfig`: `baseUri` (default `/oauth2/authorization`), `authorizationRequestResolver(OAuth2AuthorizationRequestResolver)`, `authorizationRequestRepository`, `authorizationRedirectStrategy`. `DefaultOAuth2AuthorizationRequestResolver(ClientRegistrationRepository[, baseUri])` has `setAuthorizationRequestCustomizer(Consumer<OAuth2AuthorizationRequest.Builder>)` (use it for Apple `response_mode=form_post`, or Google `prompt`).
    - `TokenEndpointConfig.accessTokenResponseClient(OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>)`. The default is the RestClient one: `RestClientAuthorizationCodeTokenResponseClient` extends `AbstractRestClientOAuth2AccessTokenResponseClient<T>` with `setRestClient`, `setHeadersConverter`/`addHeadersConverter`, `setParametersConverter`/`addParametersConverter(Converter<T, MultiValueMap<String,String>>)` and `setParametersCustomizer(Consumer<MultiValueMap<String,String>>)`: **Apple** replaces `client_secret` in the token request through `addParametersConverter` (or `setParametersCustomizer`) with the JWT signed by #2's `JwtEncoder`; no custom client class is needed (the old `*EntityConverter` types are gone).
    - `UserInfoEndpointConfig`: `userService(OAuth2UserService<OAuth2UserRequest, OAuth2User>)` (non-OIDC: GitHub), `oidcUserService(OAuth2UserService<OidcUserRequest, OidcUser>)` (Google/Entra/Apple), `userAuthoritiesMapper(GrantedAuthoritiesMapper)`.
  - **`OidcUserService`**: `loadUser(OidcUserRequest)`; setters `setOauth2UserService(OAuth2UserService<OAuth2UserRequest, OAuth2User>)`, `setClaimTypeConverterFactory`, `setRetrieveUserInfo(Predicate<OidcUserRequest>)` (use it to skip the UserInfo call for Apple, which has none), `setOidcUserConverter(Converter<OidcUserSource, OidcUser>)`. `OidcUserRequest(ClientRegistration, OAuth2AccessToken, OidcIdToken[, additionalParameters])`, `getIdToken()`. `FederatedIdentityService` wraps a delegate `OidcUserService` and returns an `OidcUser` whose `getName()` is the local user id (so `sub` of our tokens is local).
  - **`DefaultOAuth2UserService`**: `loadUser(OAuth2UserRequest)`, `setAttributesConverter(Converter<OAuth2UserRequest, Converter<Map,Map>>)`, `setRequestEntityConverter`, `setRestOperations(RestOperations)` (RestOperations, not RestClient: GitHub `/user/emails` is a second call made with it or a `RestClient`). GitHub registration needs `userNameAttributeName("id")`.
  - **Entra multi-tenant gap (confirmed)**: `OidcIdTokenValidator` compares `iss` with `ClientRegistration.getProviderDetails().getIssuerUri()` **only when that value is non-null** (`Objects.equals`), and always checks `sub`, `aud` (contains the client id), `azp`, `exp`, `iat` (clock skew default 60 s). The `common`/`organizations` discovery document carries a `{tenantid}` placeholder issuer, so setting `issuerUri` from it (what `ClientRegistrations.fromIssuerLocation` does) would reject every token. So for Entra: build the registration by hand **without** `issuerUri` and install `OidcIdTokenDecoderFactory` (a `JwtDecoderFactory<ClientRegistration>` bean, `setJwtValidatorFactory(Function<ClientRegistration, OAuth2TokenValidator<Jwt>>)`) with a custom validator that accepts `iss` matching `https://login.microsoftonline.com/{tid}/v2.0` where `tid` equals the token's `tid` claim and is in the configured allowed-tenants (or any tenant, per policy); `setJwsAlgorithmResolver` is available for Apple (ES256 client secret, RS256 id token). The default tenant-specific Entra registration can keep `issuerUri`. `ClientRegistrations` offers `fromIssuerLocation`, `fromOidcIssuerLocation`, `fromOidcConfiguration(Map)` (all return `ClientRegistration.Builder`); the builder has `issuerUri`, `jwkSetUri`, `userInfoUri`, `userInfoAuthenticationMethod`, `userNameAttributeName`, `clientAuthenticationMethod`, `scope`, `redirectUri`.
  - **`InMemoryClientRegistrationRepository` rejects an empty list** (`registrations cannot be empty`) and `oauth2Login()` needs a `ClientRegistrationRepository` bean: with no provider configured the social customizer must not call `oauth2Login` at all (or the repository bean must be conditional on at least one enabled provider), and the login-page fragment lists only configured providers.
  - **`OAuth2AuthenticationToken(OAuth2User, Collection<GrantedAuthority>, registrationId)`**, `getAuthorizedClientRegistrationId()`; it is a plain principal token with no `FactorGrantedAuthority`, so `FactorGrantor.grant(authentication, FACTOR_FEDERATED)` must be applied by the success handler (or by wrapping the user's authorities in the user service) and the login chain's session strategy changes the session id.
  - **X.509**: `X509Configurer<H>` (final): `x509AuthenticationFilter`, `x509PrincipalExtractor(X509PrincipalExtractor)`, `authenticationDetailsSource`, `userDetailsService`, `authenticationUserDetailsService(AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken>)`, `subjectPrincipalRegex(String)`. `X509PrincipalExtractor` has one method `Object extractPrincipal(X509Certificate)` (returns the principal handed to the user details service, so it can return the certificate fingerprint and a custom `AuthenticationUserDetailsService` maps fingerprint to user from `x509_certificates`). Built-ins: `SubjectDnX509PrincipalExtractor` (`setSubjectDnRegex`) and `SubjectX500PrincipalExtractor` (`setExtractPrincipalNameFromEmail`). `X509AuthenticationFilter` extends `AbstractPreAuthenticatedProcessingFilter` and has `setPrincipalExtractor`; it reads the `jakarta.servlet.request.X509Certificate` request attribute, which is what a forwarded-header filter must set (after parsing and validating the header, only from trusted proxies) so one extractor serves both transports. A dedicated TLS client-auth port is a Boot `server.ssl.client-auth=want` + an additional connector (`ServletWebServerFactory` customizer), not a Spring Security concern; Boot's `server.ssl.*` applies to the main port only.
  - **Device grant** (all `public final` configurers in `spring-security-config`): `OAuth2AuthorizationServerConfigurer.deviceAuthorizationEndpoint(Customizer<OAuth2DeviceAuthorizationEndpointConfigurer>)` and `deviceVerificationEndpoint(Customizer<OAuth2DeviceVerificationEndpointConfigurer>)`. Device authorization configurer: `deviceAuthorizationRequestConverter(s)`, `authenticationProvider(s)`, `deviceAuthorizationResponseHandler`, `errorResponseHandler`, `verificationUri(String)`. Verification configurer: `deviceVerificationRequestConverter(s)`, `authenticationProvider(s)`, `deviceVerificationResponseHandler`, `errorResponseHandler`, `consentPage(String)`. Default endpoints `/oauth2/device_authorization` and `/oauth2/device_verification` (`AuthorizationServerSettings.getDeviceAuthorizationEndpoint()` / `getDeviceVerificationEndpoint()`, so the endpoints are changed through the settings bean, not the configurer; the verification URI of the response is the verification endpoint unless `verificationUri(...)` says otherwise). The device-code token is requested at the normal token endpoint with `AuthorizationGrantType.DEVICE_CODE` (`urn:ietf:params:oauth:grant-type:device_code`); the client must register that grant type. `TokenSettings.Builder.deviceCodeTimeToLive(Duration)` (`ConfigurationSettingNames.Token.DEVICE_CODE_TIME_TO_LIVE`); the user code lifetime is the same value. `OAuth2DeviceCode` and `OAuth2UserCode` (`org.springframework.security.oauth2.core`) are `AbstractOAuth2Token` subclasses with `(tokenValue, issuedAt, expiresAt)`. `OAuth2DeviceVerificationAuthenticationToken(Authentication principal, String userCode, String clientId)`; `OAuth2DeviceAuthorizationConsentAuthenticationToken` extends the consent token with `getUserCode()`/`getRequestedScopes()`. `/oauth2/device_verification` is a GET (user-code form, which the custom page is) and POST; the verification endpoint is on the protocol chain and requires an authenticated user, so an unauthenticated visit is redirected to `/login` and resumed (same mechanism as `/oauth2/authorize`; the MFA customizer applies only to the authorize endpoint validator, device verification needs its own MFA check in the `ProtocolChainCustomizer`).
  - **JDBC authorization service**: `JdbcOAuth2AuthorizationService` already persists `user_code_*` / `device_code_*` (value, issued_at, expires_at, metadata) and `findByToken` handles token types by value lookup (a `null` type searches `state, authorization_code, access_token, oidc_id_token, refresh_token, user_code, device_code` together; typed lookups use the `user_code_value`/`device_code_value` columns). `V100` already has all eight columns, so the device grant needs **no migration**. The project wraps it as `ReuseDetectingAuthorizationService(JdbcOAuth2AuthorizationService, JdbcClient)` built in `JdbcAuthorizationServerConfiguration`; its `findByToken` and `save` must forward device/user code token types unchanged (check when implementing Task 13/14).
  - **Not verified here (needs a running context, left to the integration tests of Group 7)**: the exact JSON the stored authorization attributes take for an `OAuth2AuthenticationToken` through `OAuth2ClientJacksonModule` + `AuthorizationJacksonModuleContributor`.

## Implementation steps

### Group 1 - Verify the framework (Parallelizable: yes)

- [x] Task 1. Verify Spring Security 7.1 / Spring Authorization Server APIs with `javap` _(java-springboot)_
  - [x] Task 1.1. Read the real jars (`~/.m2`) for `OAuth2LoginConfigurer` (user service customisation, `authorizationRequestResolver`, token response client for Apple), `OidcUserService`, `DefaultOAuth2UserService`, `X509Configurer` / `X509PrincipalExtractor`, `OAuth2AuthorizationServerConfigurer.deviceAuthorizationEndpoint(...)` / `deviceVerificationEndpoint(...)`, `OAuth2DeviceCode`/`OAuth2UserCode`, and the JDBC authorization service's device-code handling
  - [x] Task 1.2. Write the confirmed signatures, defaults and gaps (for example whether the Entra multi-tenant issuer needs a custom `JwtDecoder`) into "Current code state" of this file; no source change
    - Done: facts appended to "Current code state" (only `implementation_plan.md` touched; no tests, coverage or quality gates apply, no source change; license headers not applicable).

### Group 2 - Contracts, domain, migrations, test dependency (Parallelizable: yes)

- [x] Task 2. API contracts first _(java-springboot)_
  - [x] Task 2.1. `apis/auth-server/rest-server/auth-server-api-v1.yaml`: `GET /api/account/identities` (list linked identities) and `DELETE /api/account/identities/{id}` (unlink, `401 insufficient_user_authentication` step-up response, `404`, `409` when it is the last sign-in method), every operation/parameter/schema described
  - [x] Task 2.2. `apis/auth-server/web-pages/auth-server-pages-v1.yaml`: `GET /oauth2/device_verification` (`text/html`, optional `user_code` query) and its form post; widen the `pages` group in `OpenApiConfig`
  - [x] Task 2.3. Update `apis/README.md`; regenerate with `./mvnw -pl auth-server/api/web -am generate-sources`
- [x] Task 3. Domain models and ports (`domain` has nothing but the JDK) _(java-springboot)_
  - [x] Task 3.1. `domain.social`: record `FederatedIdentity(id, userId, provider, subject, email, linkedAt, lastLoginAt)`, `IdentityProvider` enum/value (`google`, `microsoft`, `apple`, `github`), port `FederatedIdentityRepository` (`findByProviderAndSubject`, `findByUser`, `save`, `delete`, `countByUser`), `ProviderTrust` value
  - [x] Task 3.2. `domain.x509`: record `CertificateBinding(id, userId, fingerprintSha256, subjectDn, createdAt)`, port `CertificateBindingRepository`
  - [x] Task 3.3. Unit tests per record (compact-constructor validation, defensive copies, `equalsAndHashCode`), per CLAUDE.md naming
- [x] Task 4. Flyway migrations _(java-springboot)_
  - [x] Task 4.1. `V700__federated_identities.sql` (unique `(provider, subject)`, FK to `users`, tag `federated-schema`)
  - [x] Task 4.2. `V710__x509_certificates.sql` (unique fingerprint, FK to `users`, tag `x509-schema`)
- [x] Task 5. Test dependency _(java-springboot)_
  - [x] Task 5.1. Add WireMock (pinned, test scope) to the poms that need it; confirm no Docker is needed

    - Group 2 done: contracts (identities list/unlink, device verification GET page; POST form is framework-owned so not in the contract), OpenApiConfig pages group widened, apis/README updated; domain.social/domain.x509 records, enum, ProviderTrust and ports with unit tests (domain module unit tests green); V700/V710 migrations; WireMock standalone 3.13.2 pinned in root pom, test-support (in-process, no Docker). Checkstyle/PMD/SpotBugs clean. Expected temporary state: OpenApiDriftIT (2 tests) fails until the IdentityController and device verification controller exist (Groups 3-5); not weakened.

### Group 3 - Use cases and persistence adapters (Parallelizable: yes)

- [x] Task 6. `application.social` use cases (`@Service`, `@Transactional`): `FederatedIdentityService`-facing `ResolveFederatedLoginUseCase` (find, link by verified e-mail, JIT provision, refuse unverified), `LinkIdentityUseCase`, `UnlinkIdentityUseCase` (refuses the last method, audits via `RecordSecurityEventUseCase`), `ListIdentitiesUseCase`; policy as a `@Bean` in an `application` `@Configuration` _(java-springboot)_
  - [x] Task 6.1. Mockito unit tests for every use case
    - Done: `application.social` (`ResolveFederatedLoginUseCase`, `LinkIdentityUseCase`, `UnlinkIdentityUseCase`, `ListIdentitiesUseCase`, `FederatedLogin`/`FederatedLoginOutcome`, `SocialConfiguration` with the `FederatedLinkingPolicy` bean); domain additions `FederatedLinkingPolicy`, `SignInMethods`, port `GeneratedPasswordRepository` (a JIT-provisioned account holds a random unknown password, flagged so it does not count as a password sign-in method; `V701__generated_passwords.sql` adds `user_passwords.generated`, `JdbcUserAccountRepository` clears it on every password write), four exceptions, and `SecurityEventType` `IDENTITY_LINKED`/`IDENTITY_UNLINKED`/`CERTIFICATE_BOUND`/`CERTIFICATE_UNBOUND`. Linking by e-mail needs the provider AND the existing account to have verified the address (a pre-registered unverified account is refused). Unlink counts password (not generated), other identities, passkey (`PasskeyRepository.existsForAccount`) and certificates. Unit tests: one class per use case, policy, `SignInMethods`, configuration (100% line, 100% branch for every class of the package, unit-only). No new Checkstyle/PMD/CPD/SpotBugs issue.
- [x] Task 7. `application.x509`: `ResolveCertificateLoginUseCase`, `BindCertificateUseCase`, `UnbindCertificateUseCase` + tests _(java-springboot)_
  - Done: `ResolveCertificateLoginUseCase` (malformed fingerprint resolves to empty), `BindCertificateUseCase`, `UnbindCertificateUseCase` with audit; unit tests per use case (100% line/branch, unit-only); no new quality issue.
- [x] Task 8. Persistence adapters _(java-springboot)_
  - [x] Task 8.1. `infrastructure.persistence.social`: `JdbcFederatedIdentityRepository` + `FederatedIdentityRowMapper` (+ unit and `*IT` tests against the Postgres container)
  - [x] Task 8.2. `infrastructure.persistence.x509`: `JdbcCertificateBindingRepository` + row mapper + tests
  - [x] Task 8.3. A `JacksonModuleContributor` bean for federated principal types (`AuthorizationJacksonModuleContributor`)
  - Done 8.1-8.3: `social.{FederatedIdentityRowMapper,JdbcFederatedIdentityRepository,JdbcGeneratedPasswordRepository,FederatedJacksonModuleContributor}`, `x509.{CertificateBindingRowMapper,JdbcCertificateBindingRepository}`, `spring-security-oauth2-client` added to `infrastructure/persistence` (enforcer allows it; `SecurityJacksonModules` also picks `OAuth2ClientJacksonModule` up by classpath presence, the contributor makes it explicit). Unit tests with mocked `JdbcClient`/`ResultSet`, `*IT` against the Postgres container (identity, certificate, generated password incl. clearing by `JdbcUserAccountRepository`), contributor round trip of an `OAuth2AuthenticationToken` with `DefaultOAuth2User` and `DefaultOidcUser` (100% line coverage of every new class, unit+IT). Fact for Group 4: claim values must be mutable lists (`ArrayList`), the validator denies `List.of` (`ImmutableCollections$List12`) when the principal is stored. Full `./mvnw -B -fae clean verify`: only `OpenApiDriftIT` (2 tests, expected) fails; Checkstyle 0, PMD/CPD pass, SpotBugs 0 bugs in every module; `coverage`/`e2e-tests` modules were skipped by that expected failure.

### Group 4 - Social login web layer (Parallelizable: no - Task 10 uses the registrations and user services of Task 9, Task 11 the factor of Task 10)

- [x] Task 9. `api.web.social` configuration _(java-springboot)_
  - [x] Task 9.1. `SocialProperties` (`authserver.social.*`, validated record), `ClientRegistrationRepository` for the four providers (secrets only from env), Entra multi-tenant issuer validator, GitHub as plain OAuth2
  - [x] Task 9.2. `AppleClientSecretGenerator` (JWT signed with the `JwtEncoder` of #2, short lifetime, cached) wired as the token request's `client_secret`
  - [x] Task 9.3. `FederatedOidcUserService` / `FederatedOAuth2UserService` delegating to Task 6; `SocialChainCustomizer` (`LoginChainCustomizer`, `@Order(5)`) enabling `oauth2Login`; unit tests with Mockito
  - [x] Task 9.4. Account status (`AccountStatusUserDetailsService` rules) applied to a linked, disabled account
  - Done 9.1-9.4 (package `api.web.social`, all hung from `SocialProvidersCondition`, so with no `client-id` configured there is no social bean and the chain is exactly as before): `SocialProperties` (validated record, `authserver.social.providers.<id>.*`, blank client id = disabled, secrets from env only; tagged `social-config` in `application.yml` with `${AUTHSERVER_SOCIAL_*:}` placeholders and no default secret), `ClientRegistrationMapper` (Google/GitHub via `CommonOAuth2Provider`, GitHub scopes `read:user user:email`; Microsoft by hand **without** `issuerUri`; Apple by hand with an empty secret and `client_secret_post`), `EntraIssuerValidator` + `IdTokenValidatorFactory` (installed through `OidcIdTokenDecoderFactory.setJwtValidatorFactory`, keeps the framework's `OidcIdTokenValidator`; `iss` must be `https://login.microsoftonline.com/{tid}/v2.0` for the token's own `tid`, limited to `allowed-tenants`/the tenant id when given), `ApplePrivateKeyParser`, `AppleClientSecretGenerator` + `AppleTokenRequestCustomizer` (`setParametersCustomizer` replaces `client_secret` when `client_id` is Apple's) and `AppleAuthorizationRequestCustomizer` (`response_mode=form_post`; the Apple callback POST is the only CSRF exemption, and a deployment needs `SameSite=None; Secure` session cookies for Apple's cross-site post), `FederatedAccountResolver` (use case from Task 6, then the account is loaded through `AccountStatusUserDetailsService`, so a linked disabled/locked/expired account and every refusal is the same `access_denied`), `FederatedOidcUserService`, `FederatedOAuth2UserService` + `GitHubEmailClient` (verified primary e-mail from `/user/emails`; GitHub's numeric id is the subject; only scalar attributes are kept), `FederatedUserMapper` (principal named after the local username; claims normalised to ArrayList/epoch seconds/strings so the stored principal reads back; Entra's e-mail counts as verified only with `email_verified` or `xms_edov`, the nOAuth defence), `SocialChainCustomizer` (`@Order(5)`, `oauth2Login` with the server's own `/login` page, so one provider never auto-redirects) wired by `SocialConfiguration`. `spring-boot-starter-security-oauth2-client` added to `auth-server/api/web`.
  - **Deviation (9.2)**: the server's own `JwtEncoder` (#2) signs with its own published keys, which Apple cannot verify (Apple only accepts an ES256 JWT signed by the key registered in its developer account), so `AppleClientSecretGenerator` signs with a dedicated Nimbus `ECDSASigner` over the Apple key supplied from the environment (`private-key`, PKCS#8 PEM, validated at startup), cached with Caffeine for half of `client-secret-ttl` (default PT5M, at most 180 days). No `JwtEncoder` bean is added.
  - Tests (one class per production class, JUnit assertions + Mockito, keys generated at run time): 21 unit test classes in `api/web/src/test/.../social` (100% line, branch >= 75% for every class; lowest: `ApplePrivateKeyParser` 75% branch, `AppleClientSecretGenerator` 93.8% line, `FederatedUserMapper` 90.5% branch; unit-only) and `SocialLoginConfigurationIT` in `boot` (Google/Apple/GitHub configured: login page links, authorization redirects with `response_mode=form_post` and the `user:email` scope, Apple callback exempt from CSRF and others not, unknown provider never redirects). Checkstyle 0, PMD/CPD pass, SpotBugs 0 (six findings fixed while implementing: `CT_CONSTRUCTOR_THROW`, null returns of framework calls, `EI_EXPOSE_REP`). The upstream-token exchange, linking and token claims against a fake provider stay for Group 7.
- [x] Task 10. Factors and claims _(java-springboot)_
  - [x] Task 10.1. `FederatedFactor` (`FACTOR_FEDERATED`, `amr` `fed`) bean; grant it through `FactorGrantor` on success; apply the `trust-mfa` rule
  - [x] Task 10.2. `IdpClaimsContributor` (`JwtClaimsContributor`) writing `idp` and the upstream `amr`; make `sub` the local user id; check `FactorTimeline` / `MfaClaimsContributor` list repeated `amr` values once and add `mfa` correctly
  - Done 10.1-10.2: `FederatedFactor` registers two factors that a session never holds together, `FACTOR_FEDERATED` (`PRIMARY`) and `FACTOR_FEDERATED_MFA` (`PRIMARY_STRONG`), both `amr` `fed`; `FederatedAuthenticationSuccessHandler` grants one through `FactorGrantor` (the framework's token carries none), makes it the current authentication and saves the context again before the saved request resumes; `FederatedFactorSelector` picks the strong one only when the provider is `trust-mfa` **and** its upstream `amr` contains `mfa` (an upstream claim of an untrusted provider is never believed). `IdpClaimsContributor` (`JwtClaimsContributor`, `@Order(110)`, after `MfaClaimsContributor`) writes `idp`; for the strong factor it merges the upstream `amr` values (each once, so `fed`/`mfa` repeats are listed once and `mfa` once) into the `amr` list and sets `acr` to the multi-factor class; for the ordinary factor the upstream `amr` is not copied. `sub` is the principal's name, which is the local account's username (the project's `sub` for every sign-in method: `CurrentAccountResolver` and `IssuedTokenClaims` look the account up by it, there is no separate user-id `sub`), via the `local_username` attribute of `FederatedUserMapper`. `FactorTimeline`/`MfaClaimsContributor` unchanged: tests run them for real with the federated factors (ordinary alone: `[fed]`; ordinary + TOTP: `[fed, otp, mfa]`; strong: `[fed, pwd, mfa]`). Unit tests 100% line/branch (unit-only); quality clean.
- [x] Task 11. UI and account API _(java-springboot)_
  - [x] Task 11.1. `SocialLoginMethodFragment` + `templates/login-social.html` (tag `social-login-fragment`), texts in `messages.properties`
  - [x] Task 11.2. `IdentityController` implementing the generated interface, `IdentityDtoMapper`, `StepUpGuard` on unlink; controller and mapper unit tests
  - Done 11.1-11.2: `SocialLoginMethodFragment` (order 250, bean only while a provider is configured; `templates/login-social.html`, tag `social-login-fragment`, reads the providers through `@socialLoginMethodFragment`; Thymeleaf 3.1 refuses a bean reference nested in a `@{}` link, so the link is built from the provider id), messages `social.login.*` in `messages.properties`. `IdentityController` implements the generated `IdentitiesApi` (list, unlink with `StepUpGuard` first), `IdentityDtoMapper`, `IdentityExceptionHandler` (404 `urn:problem:identity:identity-not-found`, 409 `urn:problem:identity:last-sign-in-method`, step-up 401 as the rest of the account API). Unit tests for the controller (standalone MockMvc), mapper and handler, 100% line/branch (unit-only). Full `./mvnw verify -pl auth-server/boot -am`: every test passes except `OpenApiDriftIT.pagesDocs` (only the `/oauth2/device_verification` page, Group 5); `restDocs` now passes.

### Group 5 - X.509 and device grant web layers (Parallelizable: yes)

- [x] Task 12. X.509 _(java-springboot)_
  - [x] Task 12.1. `CertificatePrincipalExtractor` (`X509PrincipalExtractor`: SHA-256 fingerprint as principal), forwarded-header extractor honouring `trusted-proxies`, `X509UserDetailsService` through Task 7, `X509Factor` (`FACTOR_X509`, `amr` `sc`/`hwk`)
  - [x] Task 12.2. `X509ChainCustomizer` (`LoginChainCustomizer`, `@Order(6)`); optional extra `TomcatConnectorCustomizer` for the dedicated TLS port (off by default; keystore generated at first start under `~/.irurueta-auth-server/` as `DevKeyEncryptionSecret` does, never committed)
  - [x] Task 12.3. Unit tests (fingerprint extraction, header spoofing refused from an untrusted proxy)
- [x] Task 13. Device authorization grant _(java-springboot)_
  - [x] Task 13.1. `DeviceProtocolChainCustomizer` (`ProtocolChainCustomizer`, `@Order(2)`) enabling the device authorization and verification endpoints with the custom `/oauth2/device_verification` page
  - [x] Task 13.2. `DeviceVerificationController` implementing the generated pages interface, `templates/device-verification.html` (tag `device-verification-page`), consent hand-off through the existing consent page, rate limit on user-code attempts using `FixedWindowBuckets`
  - [x] Task 13.3. Seed `device-client` (grant `urn:ietf:params:oauth:grant-type:device_code`, public client, scopes) in `DevDataInitializer`; document why it is dev-only
  - [x] Task 13.4. Unit tests and a `*IT` slice test of the verification page
  - Done 12.1-12.3 (`api.web.x509`): `X509Properties` (validated, off by default), `CertificatePrincipalExtractor` (SHA-256 fingerprint), `ForwardedCertificateFilter` (header read only from `trusted-proxies`, sets the `jakarta.servlet.request.X509Certificate` attribute), `X509UserDetailsService` (Task 7 use case + `AccountStatusUserDetailsService`), `X509Factor` (`FACTOR_X509`, `PRIMARY_STRONG`, `amr` `sc`/`hwk`), `X509LoginFilter` + `X509AuthenticationSuccessHandler` (replaces the pre-authenticated token, grants the stamped factor, new session id), `X509ChainCustomizer` (`@Order(6)`, only `GET /login/x509`), `X509TlsConnectorCustomizer` (extra Tomcat connector, `optionalNoCA`), `X509TlsKeyStoreResolver`, `DevX509KeyStore` (dev profile only, keytool, under `~/.irurueta-auth-server/`), `X509Configuration`; `x509-config` in `application.yml`; `TestCertificates` in `test-support` (keytool at run time). Unit tests per class (line 77-100%, branch 66-100%, the two below 80% are the keytool failure path and the encoding-error log branch) and `X509LoginIT`; build gates clean.
  - Done 13.1-13.4 (`api.web.implicit`): `DeviceProtocolChainCustomizer` (`@Order(2)`), `DeviceClientAuthenticationConverter`/`Provider`/`Token` (public clients need their own authentication: Spring's PKCE one cannot serve the device flow), `DeviceVerificationRequestGuard` (rate limit + MFA before the framework converters), `DeviceVerificationRateLimiter` over `FixedWindowBuckets` + `DeviceRateLimitProperties` (`authserver.device.rate-limit.*`), `DeviceVerificationErrorHandler` (429 / second-factor page / `?error`), `DeviceVerificationController`, `templates/device-verification.html`, consent page hands the device decision to `POST /oauth2/device_verification` (contract: optional `user_code` on the consent page, `error`/`success` on the verification page); `device-client` seeded in `DevDataInitializer` (public, no `openid`: SAS refuses it in device requests). `ReuseDetectingAuthorizationService` forwards device/user code types unchanged (unit test added). `DeviceVerificationPageIT` (full flow to tokens, errors, MFA), `DeviceVerificationRateLimitIT`. Full `./mvnw -B clean verify` green, `OpenApiDriftIT` included.

### Group 6 - Polling CLI (Parallelizable: yes)

- [x] Task 14. `DeviceFlowCli` in `service-client/boot` _(java-springboot)_
  - [x] Task 14.1. Main class: POST `/oauth2/device_authorization`, print `verification_uri_complete` and user code, poll `/oauth2/token` honouring `interval` / `slow_down` / `expired_token` / `authorization_pending`; constants for defaults; JavaDoc says why it lives in `src/main`
  - [x] Task 14.2. Unit tests with Mockito for the poll loop (injected sleeper/clock bean-style), no real network
  - Done 14.1-14.2 (`service-client/boot`, package `serviceclient.device`, all active only under the `device-flow` profile): `DeviceFlowCli` (`CommandLineRunner`, poll loop), `DeviceAuthorizationClient` (`RestClient`, form POSTs to `/oauth2/device_authorization` and `/oauth2/token`), `PollOutcome`, `DeviceAuthorization`, `TokenResponse` (toString hides tokens), `DeviceFlowProperties` (`device-flow.*`), `Sleeper`/`Clock`/`DeviceFlowOutput`/`RestClient` beans in `DeviceFlowConfiguration`, `application-device-flow.yml`, pom: `spring-boot-starter-jackson`. Run: `java -jar service-client-boot.jar --spring.profiles.active=device-flow --device-flow.issuer=http://localhost:9000` (optional `--device-flow.client-id`, `--device-flow.scope`, `--device-flow.print-access-token=true`). Output lines: `User code: X`, `Verification URI: ...`, `Verification URI (complete): ...`, then `Device flow completed: token_type=Bearer expires_in=N scope=... refresh_token=true|false` (plus `Access token: ...` only when asked); non-zero exit on failure. 34 unit tests (Mockito and MockRestServiceServer, no network), about 100% line coverage of the package; no new Checkstyle/PMD/SpotBugs issues; full `./mvnw -B clean verify` green.

### Group 7 - Integration and end-to-end tests (Parallelizable: yes)

- [x] Task 15. Social `*IT` with WireMock _(java-springboot)_: first-login provisioning, verified-e-mail linking, unverified e-mail refused, Entra issuer variants, GitHub, Apple client secret shape, `idp`/`amr`/`sub` claims, untrusted-provider step-up, unlink under step-up
  - Done: `boot` tests `FakeIdentityProviders` (in-process WireMock for authorize/token/JWKS/userinfo/GitHub `/user` and `/user/emails`, RSA key generated at run time), `FakeIdentityProvidersConfiguration` (a `BeanPostProcessor` that only points the real registrations' endpoints at it), `AbstractSocialFlow`, and `SocialLoginIT` (13: provisioning, verified-e-mail linking, unverified refused, known identity, disabled account, `sub`/`idp`/`amr`/`acr` claims, GitHub verified/unverified primary e-mail, Apple ES256 client secret shape and signature, untrusted-provider step-up, unlink under step-up, last sign-in method 409/404), `SocialTrustedProviderIT` (3), `SocialEntraMultiTenantIT` (5), `SocialEntraSingleTenantIT` (2). No production defect found. All pass; coverage gate met (80/70 aggregate); Checkstyle/PMD/SpotBugs clean.
- [x] Task 16. X.509 `*IT` _(java-springboot)_: in-test CA and client certificate (generated at runtime), TLS client auth and forwarded-header paths, unknown / expired / revoked-mapping certificate refused, `amr`
  - Done: `test-support` `TestPki` (CA, server and client certificates through `keytool` in a temporary directory) and `Keytool` (shared runner), `TestCertificates.generateExpired`; `X509TlsLoginIT` (5: real TLS handshake on the dedicated port, bound certificate signs in and tokens report `sc`, unbound, no certificate, binding removed, expired) and 3 new tests in `X509LoginIT` (expired, binding removed, CA-issued certificate). **Two production defects found and fixed**: (1) an expired (or not yet valid) bound certificate signed in on both transports, `CertificatePrincipalExtractor` now yields the unreadable principal; (2) the dedicated TLS port advertised the JVM's default CAs, so a client only offered certificates of those, never a private CA's: new `AnyClientCertificateTrustManager` (advertises no authority, accepts any chain, identity = bound fingerprint + validity) wired through `X509TlsConnectorCustomizer`. Unit tests added for both (`AnyClientCertificateTrustManagerTest`, extractor and customizer tests extended).
- [x] Task 17. Device flow end to end in `e2e-tests` _(java-springboot)_: packaged jars, CLI obtains tokens after the user approves in Playwright; `DeviceFlowEndToEndIT`
  - Done: `DeviceFlowEndToEndIT` (2: approve in Playwright, the CLI jar ends with a Bearer access token for `demo`, refresh token and scopes; deny, the CLI ends non-zero), `ManagedApp.awaitExit`, `service-client-boot` dependency and `serviceclient.jar` property in `e2e-tests/pom.xml` (still last before `coverage`). **Production defect found and fixed**: the CLI failed to parse the server's device authorization answer (`interval`/`expires_in` null into a primitive `long`); `DeviceAuthorization` now maps null to the defaults (`@JsonSetter(nulls = AS_EMPTY)`), with a unit test.
- [x] Task 18. Architecture and drift checks _(java-springboot)_: run `HexagonalArchitectureTest`, `OpenApiDriftIT`; fix placement, never weaken a rule
  - Done: `HexagonalArchitectureTest` (14 per application) and `OpenApiDriftIT` (auth-server 2, bff 1, resource-server 1) pass in the full `./mvnw -B clean verify`; nothing moved, no rule weakened.

### Group 8 - Docs, shared files and final gate (Parallelizable: no - touches shared files and runs the whole build)

- [x] Task 19. Shared files _(java-springboot)_: `application.yml` (`authserver.social.*`, `authserver.x509.*`, tags `social-config` / `x509-config`), `messages.properties`, poms (oauth2-client, module wiring), `spotbugs-exclude.xml` (narrow, with reasons), `coverage/pom.xml`, `docs/antora.yml`
  - Done: verified, nothing missing (earlier groups did `application.yml` incl. `device-config`, messages, poms); no new module so `docs/antora.yml` scans and `coverage/pom.xml` need no change; no SpotBugs exclusion was needed (0 bugs).
- [x] Task 20. Update `CLAUDE.md` (feature layout, extension points used, Flyway ranges used, `DevDataInitializer` device-client note, the new dev-only code if any) _(java-springboot)_
  - Done: new #7 section, feature layout, Flyway V700/V701/V710, dev exceptions (`DevX509KeyStore`, `device-client`), pages list, `service-client` description.
- [x] Task 21. Documentation: run `/iru-update-docs` for `docs/modules/ROOT/pages/social-login.adoc`, `x509.adoc`, `device-grant.adoc` and the reference table
  - Done: three new pages, `nav.adoc`, `data-model.adoc` (V700/V701/V710, range), `reference.adoc` (pages contract list); Antora build clean.
- [x] Task 22. Final gate and PR notes _(java-springboot)_
  - [x] Task 22.1. Delegate `./mvnw -B clean verify` to the `iru-gate-runner` agent; fix Checkstyle, PMD/CPD, SpotBugs, JaCoCo (80/70) findings, never lower thresholds
    - Done: single clean `./mvnw -B clean verify` BUILD SUCCESS; Checkstyle 0, PMD/CPD pass, SpotBugs 0, JaCoCo aggregate gate met (about 99% line, 98% branch in the coverage CSV).
  - [x] Task 22.2. `iru-check-security`: no secret, key or certificate committed
    - Done: the user audited `.secrets.baseline` (53 entries, all `is_secret=false`); re-scan of every tracked and untracked non-ignored file reports 0 new and 0 unaudited findings. No key/certificate file is committed or untracked.
  - [x] Task 22.3. PR description lists every tag added (`social-login-fragment`, `federated-schema`, `x509-schema`, `device-verification-page`, `social-config`, `x509-config`, plus any added) and the **push approval design notes** (approval channel, challenge/number-matching, expiry, relation to the device grant and step-up)

## PR notes

### Docs tags added in this branch (`tag::` / `end::`)

- Required by the issue: `social-login-fragment` (`login-social.html`), `federated-schema` (`V700`), `x509-schema` (`V710`),
  `device-verification-page` (`device-verification.html`), `social-config` and `x509-config` (`application.yml`).
- Also added: `device-config` (`application.yml`), `generated-password-schema` (`V701`), `identities-api-contract` and
  `identities-schemas` (`auth-server-api-v1.yaml`), `device-verification-page-api` (`auth-server-pages-v1.yaml`).
- Java, `social`: `social-apple-secret`, `social-entra-validator`, `social-client-registrations`, `social-apple-token-request`,
  `social-account-resolver`, `social-factor-selector`, `social-factor`, `social-oauth2-user-service`, `social-success-handler`,
  `social-user-mapper`, `social-oidc-user-service`, `social-claims`, `social-identity-controller`,
  `social-login-method-fragment`, `social-registrations`, `social-chain-customizer`, `social-properties`, `social-chain`,
  `social-json-mapper` (in `FederatedJacksonModuleContributor`).
- Java, `x509`: `x509-chain`, `x509-success-handler`, `x509-forwarded-filter`, `x509-chain-customizer`, `x509-factor`,
  `x509-properties`, `x509-tls-connector`, `x509-user-details`.
- Java, `implicit` (device grant): `device-client-authentication`, `device-protocol-customizer`,
  `device-verification-controller`, `device-protocol-chain`, `device-rate-limit`, `device-guard`.
- New docs pages: `social-login.adoc`, `x509.adoc`, `device-grant.adoc` (nav, `data-model.adoc` and `reference.adoc` updated).

### Push approval: design notes (no code in this PR)

- **Approval channel**: a push notification (APNs / FCM) to a mobile app on a device the user enrolled, with the user's
  signed-in session on the authorization server as the party being approved. Enrolment binds a device key pair (public key
  stored server side, private key in the secure enclave / keystore) to the account, from an already authenticated session
  behind `StepUpGuard`, the same shape as passkeys and the phone.
- **Registration in the framework**: a `SECOND` `AuthenticationFactor` (its own `FACTOR_*` authority, `amr` `swk`/`otp` as
  fits), a `SecondFactorFragment` showing "waiting for approval", a `SecondFactorEnrolmentQuery` bean (a user with an
  enrolled device requires MFA), an `AuthenticationProvider` using the shared lockout and security-event use cases, and its
  own Flyway range. No shared file is edited, as for TOTP and one-time tokens.
- **Challenge and number matching**: each login attempt creates a single-use challenge bound to the session id and to the
  pending authorization request. The login page displays a two-digit number; the app shows three candidates and the user
  must pick the one on the screen (number matching), which defeats "prompt bombing" / MFA fatigue. The approval is a response
  signed with the device key over (challenge, number, client id, requested scope, expiry); the server verifies the signature
  against the enrolled public key, so the push payload carries no secret and a stolen notification cannot approve.
- **Expiry and limits**: challenge lifetime of about 60 seconds (single use, consumed on approve or deny), a small cap of
  pending challenges per user, rate limit through `FixedWindowBuckets`, failures counted by the shared second-factor
  lockout, deny reported as a security event; the login page polls or uses SSE, and falls back to another factor on expiry.
- **Relation to the device grant**: the approval of a push notification is about the *user's own sign-in* and is unrelated to
  the device authorization grant's user code, though both are out-of-band approvals. A device grant verification already runs
  the MFA policy (`DeviceVerificationRequestGuard`), so a user whose second factor is a push approval would approve it while
  signing in on the verification page; the consent screen of the device flow is a different step and stays a click.
- **Relation to step-up**: an approved push is a reported `SECOND` factor, so it produces `amr` and `mfa`, satisfies
  `StepUpGuard` (RFC 9470) and is counted by `FactorTimeline` for `auth_time`; step-up for a sensitive operation sends the
  user to a fresh challenge with number matching. It is never a `REMEMBERED` factor.
- **Risks to review**: device loss (recovery through other factors or recovery codes, revoke device), notification
  availability (offline fallback), and the push provider as a third party (payload carries only an opaque challenge id).

### Gate status

- `detect-secrets` (Task 22.2) awaits the user's audit: see the findings reported with this run; not labelled in `.secrets.baseline`.
