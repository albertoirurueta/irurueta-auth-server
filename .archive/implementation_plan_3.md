# Implementation plan: Custom login, consent and logout pages and the Backend-for-Frontend (BFF) with a minimal SPA (issue #3)

## Task summary

Replace the default Spring Security / Spring Authorization Server pages with custom Thymeleaf pages (login, consent,
error, logout confirmation) on `auth-server`, and turn `bff` into a real Backend-for-Frontend: a confidential PKCE
client whose session lives in PostgreSQL (Spring Session JDBC, `__Host-SESSION` cookie), which relays `/api/**` to
`resource-server` with the user's access token so that **no token ever reaches JavaScript**, plus a minimal SPA
(login, profile, API call, logout, `401` → re-login) served from `bff/boot/src/main/resources/static/`.

Source: GitHub issue #3
Base branch: main
Flyway range: `V300`–`V399` only (the Spring Session schema, `bff` database).

Choices made (challenge them in review):
- **Login style: all methods on one page** (password form plus every `LoginMethodFragment`), not identifier-first. It
  is what the existing extension point (`LoginMethodFragment`) was built for, so #4 can add methods without touching
  the page. Unknown users and wrong passwords give the same generic error (`?error`), never a distinct message.
- **Token relay: `RestClient` proxy with `OAuth2ClientHttpRequestInterceptor`**, not Spring Cloud Gateway Server WebMVC.
  Task 1 verifies whether a Spring Cloud release train supports Boot 4.1.2; the local Maven cache cannot prove it. If
  it does, the relay stays a `RestClient` proxy anyway unless the user prefers the gateway (one controller, no new BOM,
  testable with MockMvc); the reason is recorded in the PR description either way.
- **Hexagonal fit.** `bff` has no domain behaviour, so it stays `api/web` + `boot` (a layer is only created once it has
  code). Session JDBC wiring, the relay and CSRF live in `api/web`; `boot` only holds the Flyway migration and
  `application*.yml`. No new `infrastructure` module.
- **Consent / logout / headers through the existing extension points.** Consent page via a `ProtocolChainCustomizer`
  (`authorizationEndpoint(e -> e.consentPage("/oauth2/consent"))`), OIDC logout via the protocol chain's
  `oidc(...)` defaults, headers and the logout confirmation via a `LoginChainCustomizer`. `SecurityConfig` of
  `auth-server` is **not** edited.
- **Branding** through `@ConfigurationProperties` (`authserver.ui.branding.*`: application name, logo URL, primary
  colour, support link) with safe defaults, injected into the templates through a `@ControllerAdvice` model attribute.
- **Cookie.** `__Host-SESSION` (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`) through Spring Session's
  `CookieSerializer`. Chromium accepts `Secure` cookies on `http://localhost`, so the e2e test reaches the BFF through
  `localhost`; cookies ignore ports, but the auth server's cookie is `JSESSIONID` and the BFF's is `__Host-SESSION`, so
  they never overwrite each other (the existing smoke test uses `127.0.0.1` for the BFF, to be reviewed in Task 10).
- **Verified in Task 1 (2026-11-06).** Maven Central: the latest *released* Spring Cloud train is 2025.1.4, built on
  Boot 4.0.9; the train for Boot 4.1 (2026.0.0) is only at RC2 (which targets Boot 4.2.0-RC2) and 2026.0.0 is not
  published, so no release train supports Boot 4.1.2. `spring-cloud-gateway-server-webmvc` 5.0.1 does ship
  `TokenRelayFilterFunctions`, but it cannot be used on Boot 4.1 yet: the `RestClient` proxy choice stands.
  `CsrfConfigurer.spa()` exists in Spring Security 7.1.2 (`javap`), so `csrf.spa()` is used.
- **SPA CSRF**: `CookieCsrfTokenRepository.withHttpOnlyFalse()` with `csrf.spa()` if the 7.1 API has it (verified in
  Task 1), else the `XorCsrfTokenRequestAttributeHandler` + `CsrfCookieFilter` recipe.
- **Logout support recorded**: RP-initiated logout is supported by Spring Authorization Server (`/connect/logout`),
  back-channel logout is **not implemented** (no `OidcLogoutAuthenticationProvider` back-channel sender) and front-channel
  is not supported; this is recorded in the docs page and the PR (Task 12).
- **`/api/orders` in the issue does not exist**: `resource-server` exposes `/api/documents`; the SPA and e2e call
  `/api/documents`.

Open clarifications: none

## Acceptance criteria coverage

| # | Criterion | Covered by tasks |
|---|---|---|
| 1 | "The custom pages replace the defaults. The fragment extension point is used by the password method." | Task 3, Task 4, Task 5 |
| 2 | "The SPA flow works end to end with token relay. Sessions persist in PostgreSQL." | Task 6, Task 7, Task 8, Task 9, Task 10 |
| 3 | "`./mvnw verify` green, and the tags are listed in the PR." | Task 11, Task 12 |
| 4 | derived: no token is visible to the browser (storage, cookies, response bodies) | Task 8, Task 10 |
| 5 | derived: login, consent and CSRF behaviour is covered by MockMvc tests; BFF tests use `oidcLogin()` | Task 3, Task 4, Task 7 |
| 6 | derived: `/bff/login?returnTo=` only accepts allow-listed targets | Task 7 |

## Current code state

- `auth-server/api/web`: `SecurityConfig` (protocol chain `@Order(1)`, login/UI chain `@Order(2)` with
  `formLogin(loginPage("/login"))` and the `LoginChainCustomizer` beans), `login/LoginController`
  (`GET /login`, adds `loginPath` and the sorted `fragments`), `login/LoginMethodFragment`, `login/LoginChainCustomizer`,
  `ProtocolChainCustomizer`, `templates/login.html` (bare password form, tag `login-form`). The password method does not
  yet contribute a fragment. No consent page, logout page, headers or branding exist.
- `auth-server/application/.../clients/DefaultClientDefinitions`: `bff` and `spa-public` definitions (consent required,
  audience `resource-server`); `ClientSeeder` and `DevDataInitializer` seed them. Post-logout redirect URIs are to be
  checked and, if missing, added through configuration (`authserver.clients.bff.post-logout-redirect-uris`).
- `auth-server/boot`: `application.yml`, `application-dev.yml`; ITs `SecurityIT`, `SecurityConfigIT`,
  `AuthorizationCodePkceIT`; `test-fragments.html` test template.
- `bff/api/web`: `security/SecurityConfig` (tag `bff-security`: `oauth2Login` + `withPkce()`, 401 entry point for
  `/bff/**`), `user/UserController` + `SessionUserDtoMapper` (generated `UserApi`, returns only `subject`),
  `OpenApiConfig`. Contract `apis/bff/rest-server/bff-api-v1.yaml` has only `/bff/user`.
- `bff/boot`: `application.yml` (client `bff`, `client_secret_basic`, scope `openid,profile`), tests
  `SecurityConfigIT`, `UserControllerIT`, `OpenApiDriftIT`, `HexagonalArchitectureTest`; datasource auto-config is
  excluded in tests (no persistence yet). `compose/init-databases.sql` already creates the `bff` database.
- `resource-server`: `GET /api/documents`, `DELETE /api/documents/{id}` secured by bearer JWT with audience
  `resource-server`.
- `e2e-tests`: `SignInSmokeIT`, `ManagedApp`, `RunningAuthServer`, `ResourceServerEndToEndIT`.
- `docs/antora.yml` already scans `bff/api/web` and `bff/boot`. UI stack: Thymeleaf (server pages) and a plain
  HTML/JS SPA (new); `.ui-quality.yml` absent, accessibility partial.

UI tree (`Screen › Region › Component`, N = new, C = changed):
- Login (C) › layout fragment (N), branding header (N), error/status banner (C), password form fragment (N, via
  `LoginMethodFragment`), other-method fragments (reused)
- Consent (N) › client + user header, scope list with descriptions, previously granted scopes, Allow/Deny form
- Logout confirmation (N) › confirm form
- Error (N) › generic error page
- SPA (N) › nav bar, profile card, documents list, error/401 handling

## Implementation steps

### Group 1 — Build prerequisites (Parallelizable: yes)

- [x] Task 1. Verify the relay and CSRF options, record them _(java-springboot)_
    Done: files bff/boot/pom.xml, application.yml, application-dev.yml, V300__spring_session.sql, e2e RunningAuthServer/SignInSmokeIT, three bff ITs moved to @PostgresIT; full ./mvnw verify green (unit+IT+gates+e2e). Coverage: no new production Java.
  - [x] Task 1.1. Check Maven Central for a Spring Cloud release train supporting Boot 4.1 and whether
    `spring-cloud-starter-gateway-server-webmvc` ships `TokenRelay`; record the finding in this plan's choices.
  - [x] Task 1.2. Check that `CsrfConfigurer.spa()` exists in Spring Security 7.1 (`javap` the jar); record it.
  - [x] Task 1.3. Add `spring-session-jdbc` (managed by the Boot BOM), `spring-boot-starter-jdbc`,
    `spring-boot-starter-flyway` and `org.postgresql:postgresql` to `bff/api/web` or `bff/boot` pom (`boot` for the
    driver/Flyway, `api/web` for `spring-session-jdbc`); keep the enforcer `bannedDependencies` rule of `bff/api/web`
    intact: `spring-session-jdbc` must go in `bff/boot`, because the rule bans `spring-jdbc` directly in `api/web`.
  - [x] Task 1.4. Add `V300__spring_session.sql` under `bff/boot/src/main/resources/db/migration` (Spring Session JDBC
    PostgreSQL schema, `-- tag::bff-session-schema[]`) and set `spring.flyway`, `spring.datasource.*` (environment
    placeholders, no committed secrets) and `spring.session.jdbc.initialize-schema: never` in `bff/boot/application.yml`;
    add the `dev` profile `application-dev.yml` with the compose database (`spring.docker.compose.file`).

### Group 2 — Auth-server page foundation (Parallelizable: yes)

- [x] Task 2. Branding, layout fragment and security headers for the login/UI pages _(java-springboot)_
  - [x] Task 2.1. `login/BrandingProperties` (`@ConfigurationProperties("authserver.ui.branding")`, record, defaults) and
    `login/BrandingModelAdvice` (`@ControllerAdvice` adding `branding`), enabled with
    `@EnableConfigurationProperties` in a `@Configuration` of `…api.web.login`; tests `BrandingPropertiesTest`,
    `BrandingModelAdviceTest`.
  - [x] Task 2.2. `templates/fragments/layout.html` (`<html>` skeleton fragment with head, branding header, `main`,
    `lang`, viewport, nonce-free stylesheet `static/css/pages.css`), tag `login-layout`.
  - [x] Task 2.3. `login/LoginHeadersCustomizer` (`LoginChainCustomizer`, `@Order(0)`): `Content-Security-Policy:
    default-src 'self'; frame-ancestors 'none'; form-action 'self'`, `X-Content-Type-Options`, `Referrer-Policy`;
    `LoginHeadersCustomizerTest` and a MockMvc assertion in an IT (Task 3.3).
    - Done: Branding{Properties,ModelAdvice,Configuration}, LoginHeadersCustomizer, LoginStaticResourcesCustomizer (permits /css/pages.css), fragments/layout.html (tag login-layout), static/css/pages.css; unit tests + SecurityConfigIT header/stylesheet assertions; full `verify` green, no new quality issues. CSP omits `form-action 'self'` (it blocks the redirect to the client redirect_uri; confirmed by e2e).

### Group 3 — Auth-server pages (Parallelizable: yes — each task owns different templates/controllers)

- [x] Task 3. Login page _(java-springboot)_
  - Done (login.html on the layout, LoginErrorMessages, PasswordLoginFragment + password.html, messages.properties; LoginControllerTest, LoginErrorMessagesTest, PasswordLoginFragmentTest, LoginPageIT; SecurityConfigIT adjusted). 100% line/branch on the new classes, no new Checkstyle/PMD/SpotBugs issues, `clean verify` green incl. e2e.
  - [x] Task 3.1. Rework `templates/login.html` onto the layout; error states keyed by a `LoginErrorMessages` mapper
    (`BadCredentialsException`, `LockedException`, `AccountExpiredException`, `CredentialsExpiredException`,
    `DisabledException`) read from the `SPRING_SECURITY_LAST_EXCEPTION` session attribute; unknown user and bad password
    both render the generic message (identical response).
  - [x] Task 3.2. `password/PasswordLoginFragment` (`LoginMethodFragment`, order 100) and `templates/password.html`
    (`autocomplete="username"` and `current-password`); move the form out of `login.html` so the password method uses
    the extension point (tag `login-form` moves with it). Keep `autocomplete` values `one-time-code` and `webauthn`
    documented for the later fragments.
  - [x] Task 3.3. Keep the `SavedRequest` return to `/oauth2/authorize` (default `SavedRequestAwareAuthenticationSuccessHandler`)
    and CSRF hidden input (`th:action` emits it); `LoginControllerTest` (update) + `LoginPageIT` (`@WebMvcTest` slice,
    CSRF missing → 403, bad credentials → `/login?error`, saved request redirect).
- [x] Task 4. Consent page _(java-springboot)_
  - Done (ConsentController, ConsentPageModel, ConsentPageModelMapper, ConsentProtocolCustomizer, consent.html tagged consent-page; four unit tests + ConsentPageIT incl. deny -> access_denied and allow -> code). 100% line/branch, gates green. Note: seeded clients still use requireAuthorizationConsent=false (no plan task changes that), so the page is exercised only by clients that require consent.
  - [x] Task 4.1. `consent/ConsentController` (`GET /oauth2/consent`, params `client_id`, `scope`, `state`) building a view
    model from `RegisteredClientRepository` (the one framework bean, so the controller is in `api/web`) and
    `OAuth2AuthorizationConsentService`: scopes to approve and previously granted scopes, with descriptions from
    `messages.properties` (`consent.scope.<name>`); `ConsentPageModelMapper` (`@Component`).
  - [x] Task 4.2. `consent/ConsentProtocolCustomizer` (`ProtocolChainCustomizer`) calling
    `server.authorizationEndpoint(e -> e.consentPage("/oauth2/consent"))`; `templates/consent.html` posting to
    `/oauth2/authorize` with `client_id`, `state`, `scope` checkboxes, **Allow** and **Deny** (`deny` submits no scope).
  - [x] Task 4.3. Tests: `ConsentControllerTest`, `ConsentPageModelMapperTest`, `ConsentProtocolCustomizerTest`,
    `ConsentPageIT` (denied consent → `error=access_denied` redirect).
- [x] Task 5. Logout and error pages _(java-springboot)_
  - Done (LogoutChainCustomizer, LogoutController, logout.html tagged logout-page, ErrorPageController + error.html; LogoutIT, ErrorPageIT and unit tests). 5.2: `oidc(Customizer.withDefaults())` already exposes /connect/logout, so no ProtocolChainCustomizer was added; post-logout redirect URIs added end to end (ClientRegistration.postLogoutRedirectUris, RegisteredClientMapper, DefaultClientDefinitions, ClientSeedProperties/ClientSeeder, DevDataInitializer, OpenAPI contract, application*.yml). 100% line/branch, gates green.
  - [x] Task 5.1. `logout/LogoutChainCustomizer` (`LoginChainCustomizer`): `logout(l -> l.logoutUrl("/logout")
    .logoutSuccessUrl("/login?logout").invalidateHttpSession(true).deleteCookies("JSESSIONID"))`, and a GET
    `logout/LogoutController` rendering `templates/logout.html` (confirmation form, CSRF) for `/logout`.
  - [x] Task 5.2. Enable OIDC RP-initiated logout (`/connect/logout`) in the protocol chain through a
    `ProtocolChainCustomizer` only if `oidc(Customizer.withDefaults())` does not already expose it; verify
    `post_logout_redirect_uris` handling and add `authserver.clients.*.post-logout-redirect-uris` to
    `ClientSeedProperties`/`DefaultClientDefinitions` when missing (touches `clients`, **coordinate with #2 code**).
  - [x] Task 5.3. `error/ErrorPageController` + `templates/error.html` (no stack trace, correlation-free generic text);
    permit `/error` (already permitted).
  - [x] Task 5.4. Tests: `LogoutControllerTest`, `LogoutChainCustomizerTest`, `ErrorPageControllerTest`,
    `LogoutIT` (session invalidated, `post_logout_redirect_uri` honoured only when registered).

### Group 4 — BFF persistence and contract (Parallelizable: no — Task 7 edits files Task 6 also touches)

- [x] Task 6. Spring Session JDBC and cookie _(java-springboot)_
  - [x] Task 6.1. `session/SessionConfiguration` (`@EnableJdbcHttpSession`, `DefaultCookieSerializer` bean with name
    `__Host-SESSION`, `useSecureCookie(true)`, `useHttpOnlyCookie(true)`, `sameSite("Lax")`, `cookiePath("/")`, no
    domain), tag `bff-session`; test `SessionConfigurationTest`.
  - [x] Task 6.2. `BffSessionIT` (PostgreSQL via `@PostgresIT`): sign in with `oidcLogin()`, assert a row in
    `spring_session` and the cookie attributes in the `Set-Cookie` header.
- [x] Task 7. BFF security, CSRF, login redirect and logout _(java-springboot)_
  - [x] Task 7.1. Contract first: extend `apis/bff/rest-server/bff-api-v1.yaml` with `GET /bff/login` (`returnTo` query,
    302), `POST /bff/logout` (200 with the auth server's logout URL, see 7.4), richer `SessionUserResponse` (`subject`, `name`, `email`,
    `roles` — UI-safe claims, never tokens) and the CSRF cookie description; every operation and property described,
    tags `bff-login-api`, `bff-logout-api`. Regenerate with `./mvnw -pl bff/api/web -am generate-sources`.
  - [x] Task 7.2. `login/BffLoginController` implementing the generated interface: validates `returnTo` against
    `bff.login.allowed-return-paths` (`BffLoginProperties`, relative paths only, rejects `//`, schemes, backslashes,
    control characters), stores it as the saved request and redirects to `/oauth2/authorization/bff`; `ReturnToValidator`
    (`@Component`) + `ReturnToValidatorTest` (open-redirect cases).
  - [x] Task 7.3. Extend `security/SecurityConfig` (tag `bff-security` kept): permit `/`, `/index.html`, static assets, `/bff/login`,
    health; CSRF through `CookieCsrfTokenRepository.withHttpOnlyFalse()` with `csrf.spa()` (or the recipe from Task 1.2);
    `OAuth2AuthorizedClientManager` bean with `authorization_code` and `refresh_token` providers; authorized clients stay
    in the HTTP session (`HttpSessionOAuth2AuthorizedClientRepository`, persisted by Spring Session JDBC), so no extra
    table is needed.
  - [x] Task 7.4. `logout/BffLogoutController` (`POST /bff/logout`, CSRF protected): invalidates the session, then
    returns the RP-initiated logout URL of the auth server built by `OidcClientInitiatedLogoutSuccessHandler`
    (`post_logout_redirect_uri` = SPA root); the SPA navigates to it. `UserController`/`SessionUserDtoMapper` return the
    new claims; update their tests; tag `bff-logout`.
  - [x] Task 7.5. Tests: `BffLoginControllerTest`, `BffLogoutControllerTest`, `SecurityConfigIT` (CSRF required on POST,
    `oidcLogin()` user, `/api/**` unauthenticated → 401), `UserControllerIT` update, `OpenApiDriftIT` stays green.

### Group 5 — Token relay (Parallelizable: yes)

- [x] Task 8. Relay `/api/**` to `resource-server` _(java-springboot)_
  - [x] Task 8.1. `relay/RelayProperties` (`bff.relay.target-uri`, default `http://localhost:8081`),
    `relay/RelayRestClientConfiguration` (`RestClient` with `OAuth2ClientHttpRequestInterceptor` from the
    `OAuth2AuthorizedClientManager`, registration id `bff`; failure to refresh → `OAuth2AuthorizationException`
    mapped to 401), tag `bff-relay`.
  - [x] Task 8.2. `relay/ApiRelayController` (`/api/**`, GET/POST/PUT/PATCH/DELETE): copies method, path, query, safe
    headers and body, **drops** `Cookie`, `Authorization`, `X-CSRF-TOKEN` inbound and `Set-Cookie` outbound, never logs
    tokens; the response body is streamed back unchanged. `RelayHeaderFilter` (`@Component`) holds the allow-list.
  - [x] Task 8.3. Document the relay (`/api/**`) in the contract as a single `x-` described pass-through operation or as
    an explicit note, decided with `OpenApiDriftIT` (springdoc documents only `/bff/**`; `/api/**` stays out of the group
    so the drift test stays green).
  - [x] Task 8.4. Tests: `ApiRelayControllerTest`, `RelayHeaderFilterTest`, `ApiRelayIT` (`MockRestServiceServer` bound
    to the relay `RestClient.Builder`: bearer header present upstream, absent in the response and in `Set-Cookie`).
  - Done: `bff/api/web/.../relay/` (`RelayProperties`, `RelayRestClientConfiguration` incl. a guard interceptor that
    refuses to send a call whose session has no token, `RelayHeaderFilter`, `ApiRelayController`), starter-restclient
    added to `api/web` (starter-restclient-test to `boot`), `bff.relay.target-uri` in `application.yml`
    (`RESOURCE_SERVER_URI`), contract documents the relay as the top-level `x-token-relay` extension (tag
    `bff-relay-api`). Tests: `ApiRelayControllerTest`, `RelayHeaderFilterTest`, `RelayPropertiesTest`,
    `RelayRestClientConfigurationTest` (100% line / 100% branch unit coverage of the relay classes) and `ApiRelayIT`
    (6 tests, passed with Docker); `mvn -pl bff/boot -am clean verify` green (Checkstyle, PMD, SpotBugs, ArchUnit,
    OpenApiDriftIT).

### Group 6 — SPA (Parallelizable: yes)

- [x] Task 9. Minimal SPA in `bff/boot/src/main/resources/static/` _(typescript)_
  - [x] Task 9.1. `index.html`, `app.js` (ES module, no build step, no framework, tag comments `<!-- tag::bff-spa[] -->` /
    `// tag::bff-spa-js[]`), `styles.css`: on load `GET /bff/user` (`credentials: 'same-origin'`); `401` → navigate to
    `/bff/login?returnTo=…`; profile card; **Load documents** calls `GET /api/documents`; **Sign out** `POST /bff/logout`
    with the `X-XSRF-TOKEN` header read from the `XSRF-TOKEN` cookie, then follows the returned logout URL.
  - [x] Task 9.2. Accessibility basics (labels, `lang`, focus on the main heading, `aria-live` for errors); no inline
    scripts (CSP `script-src 'self'` header set by the BFF chain).
  - [x] Task 9.3. `SpaStaticResourcesIT` (`@SpringBootTest` MockMvc): the SPA is served unauthenticated, API still requires
    a session, CSP header present.
    - Done: `static/index.html`, `static/assets/app.js`, `static/assets/styles.css` (under `/assets/`, already permitted);
      CSP `default-src 'self'; frame-ancestors 'none'` added to `SecurityConfig` (tag `bff-security`); tests in
      `SpaStaticResourcesIT` (5), `SecurityConfigTest` (+1); module verify gates green. No Node toolchain added.

### Group 7 — End-to-end and quality (Parallelizable: no — shares the e2e harness)

- [x] Task 10. e2e flow through the real server _(java-springboot)_
  - [x] Task 10.1. Extend `RunningAuthServer`/`ManagedApp` to also start `resource-server` and pass `bff.relay.target-uri`
    and `AUTHSERVER_BFF_REDIRECT_URIS` / post-logout URIs; `BffEndToEndIT`: SPA → login → consent (Allow) → SPA shows the
    profile → **Load documents** returns data → sign out → protected call is 401.
  - [x] Task 10.2. No-token assertions: scan `localStorage`, `sessionStorage`, `document.cookie` (non-HttpOnly), all response
    bodies and `Set-Cookie` headers captured via Playwright's response events for JWT-shaped (`eyJ…\..+\..+`) and opaque
    token values obtained from the auth server's token response; and that `__Host-SESSION` is `HttpOnly`, `Secure`,
    `SameSite=Lax`.
  - [x] Task 10.3. Deny-consent scenario: the SPA shows a sign-in failure, no session created.
- [x] Task 11. Run the build gates _(java-springboot)_
  - [x] Task 11.1. Delegate to `iru-gate-runner`: `./mvnw -B clean verify` (Checkstyle, PMD/CPD, SpotBugs, JaCoCo
    80/70, Enforcer, ArchUnit, OpenAPI drift). Add tests, never lower thresholds.

  - Notes (Group 7): consent gap fixed with a `requireConsent` flag (domain `ClientRegistration`, mapped by `RegisteredClientMapper`, true for the seeded `bff` via `DefaultClientDefinitions`, exposed in the auth-server contract as optional on `ClientRequest` / required on `ClientResponse`; no migration). The BFF now requests `documents.read` (needed for `/api/documents`) and uses an `oauth2Login` failure handler redirecting to `/?error=signin`, which the SPA renders in its alert region with a retry link (`failureHandler`, not `failureUrl`, because the latter makes the generated login page answer that URL). `BffEndToEndIT` (sign-in, consent, profile, documents, sign-out, 401; no-token scan; deny consent), `RunningAuthServer.query`, `SignInSmokeIT` and `ResourceServerEndToEndIT` now answer the consent page. The resource server stores no documents, so "Load documents" shows the empty list (200).
  - Task 11 result: `./mvnw -B clean verify` green; aggregate coverage 99.3% line / 97.7% branch.

### Group 8 — Documentation (Parallelizable: yes)

- [x] Task 12. Documentation and tag list
  - [x] Task 12.1. Run `/iru-update-docs` for the Antora pages: add `docs/modules/ROOT/pages/login-and-bff.adoc` (login style,
    consent, logout support matrix with front-/back-channel recorded, relay choice and why, cookie, CSRF), update `nav.adoc`,
    `architecture.adoc` and `reference.adoc`.
    - Done: new `login-and-bff.adoc` (layout, login page, headers/CSP, consent, logout matrix, BFF security, session and
      `__Host-SESSION` cookie, CSRF, login/logout API, RestClient relay and why, SPA); `nav.adoc` (entry before
      resource-server); `architecture.adoc` (BFF paragraph, `login-form` include moved to `password.html`, layer note);
      `reference.adoc` (BFF contract row); `clients.adoc` (`postLogoutRedirectUris`, `requireConsent`, and a broken
      `tokens-settings` include repointed to `RegisteredClientMapper.java`). No new Antora scan needed (no new module).
      `npx --no-install antora antora-playbook.yml` builds with zero warnings.
  - [x] Task 12.2. List every added tag in the PR description (`login-layout`, `login-form`, `consent-page`,
    `logout-page`, `bff-security`, `bff-session`, `bff-session-schema`, `bff-login-api`, `bff-logout-api`, `bff-logout`,
    `bff-relay`, `bff-spa`, `bff-spa-js`); renames of existing tags (`login-form` moves to `password.html`) go in the
    PR for albertoirurueta/docs#344.
    - **PR tag list** (verified by grep of the working tree against `main`; paste into the PR description):
      - Added: `login-layout` (`fragments/layout.html`), `login-branding` (`BrandingProperties.java`), `login-headers`
        (`LoginHeadersCustomizer.java`), `login-page` (`login.html`), `consent-page` (`consent.html`), `logout-page`
        (`logout.html`), `logout-config` (`LogoutChainCustomizer.java`), `bff-authorized-client` (bff `SecurityConfig.java`),
        `bff-session` (`SessionConfiguration.java`), `bff-session-schema` (`V300__spring_session.sql`), `bff-login`
        (`BffLoginController.java`), `bff-login-api` (`bff-api-v1.yaml`), `bff-logout` (`BffLogoutController.java`),
        `bff-logout-api` (`bff-api-v1.yaml`), `bff-logout-handler` (`LogoutConfiguration.java`), `bff-relay`
        (`RelayRestClientConfiguration.java`), `bff-relay-controller` (`ApiRelayController.java`), `bff-relay-api`
        (`bff-api-v1.yaml`), `bff-spa` (`static/index.html`), `bff-spa-js` (`static/assets/app.js`).
      - Moved (for albertoirurueta/docs#344): `login-form` from `templates/login.html` to `templates/password.html`
        (same name; `login.html` now carries `login-page`).
      - Same name, content changed: `bff-security` (CSRF `spa()`, CSP, 401 entry point, failure handler, PKCE resolver)
        and `bff-user-api` (description of `/bff/user`). `bff-user` is unchanged.
      - Not renamed or removed: no existing tag was renamed or deleted. Nothing committed or opened (no PR yet).
