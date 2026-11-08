# Implementation plan: Implicit flow (opt-in legacy demo), client credentials and service-to-service (private_key_jwt, mTLS, token exchange) (issue #8)

## Task summary

Close the 1.0.0 series of the guide *Building an Authorization Server from Scratch* (docs#159, docs#345) with the
non-interactive flows and an isolated legacy implicit demo:

1. **Implicit, default server**: `response_type=token` is answered `unsupported_response_type`, pinned by a test.
2. **Implicit, opt-in `legacy-implicit` profile** (off by default): a custom authorization-request converter, provider
   and response handler that accept `response_type=token` **only** for `legacy-implicit-spa`, issue a short-lived,
   audience-restricted access token (no refresh token), require an exact redirect URI and `state`, and redirect with
   `#access_token=…&token_type=Bearer&expires_in=…&state=…`; plus a static demo page.
3. **`client_credentials` in `service-client`**: `AuthorizedClientServiceOAuth2AuthorizedClientManager`, `RestClient` +
   `OAuth2ClientHttpRequestInterceptor`, cached token refreshed before expiry, calling the resource server's
   `GET /api/documents` through a client generated from its contract.
4. **Client authentication**: `client_secret_basic`; `private_key_jwt` (registered JWK set or `jwkSetUrl`, `jti` replay
   protection); mTLS (`tls_client_auth` and `self_signed_tls_client_auth`) with certificate-bound tokens
   (`cnf.x5t#S256`) checked by the resource server; DPoP (`cnf.jkt`) on both sides.
5. **Token exchange** (RFC 8693): server enablement, `TokenExchangeOAuth2AuthorizedClientProvider` in `service-client`,
   `act` claim, downstream call on behalf of the user.
6. **PAR** (`/oauth2/par`) as an opt-in hardening switch.

Source: GitHub issue #8
Base branch: main
Flyway range: `V800`–`V899` only (`V800` `client_assertion_jtis`).
Feature packages (auth-server): `implicit` (already holds the device grant; the legacy implicit classes join it, prefixed
`LegacyImplicit`), new `clientauth` (client authentication: assertion replay, registered JWKs, mTLS verifier, DPoP) and
`exchange` (token exchange), new `par` (pushed authorization requests). `clients` is touched only for the new
client settings (shared, see Task 2).

Choices made (challenge them in review):
- **Token exchange topology (user's choice)**: `service-client` exchanges. Under a `token-exchange` profile it takes a
  user's access token as `subject_token`, uses its own client-credentials token as `actor_token`
  (`TokenExchangeOAuth2AuthorizedClientProvider` with subject/actor token resolvers), gets a `resource-server` token
  carrying `act {sub: service-client}` and calls `GET /api/documents` as that user (the resource server answers with
  the user's own documents, because `sub` stays the user). The e2e test obtains the user token through the browser.
- **private_key_jwt keys (user's choice)**: a registered public JWK set stored in a custom client setting
  (`settings.client.jwks`, admin API field `jwks`), resolved by a `JwtDecoderFactory<RegisteredClient>` that falls back to
  the framework's `JwtClientAssertionDecoderFactory` (`jwkSetUrl`). `service-client` reads its private key (PKCS#8 PEM)
  from `SERVICE_CLIENT_PRIVATE_KEY` / a file path; tests generate the key pair at run time. No key is committed.
- **tls_client_auth trust (user's choice)**: both mTLS methods. `tls_client_auth` installs a
  `certificateVerifier` that validates the presented chain (PKIX, no revocation, documented) against
  `authserver.mtls.trusted-authorities` (PEM file paths) **before** the framework's subject-DN comparison, because the
  TLS port's `AnyClientCertificateTrustManager` accepts any chain; with no trusted authority configured
  `tls_client_auth` is refused. `self_signed_tls_client_auth` pins the certificate through the client's JWK set
  (`x5c`): registered JWKs first, else the framework's self-signed check (`jwkSetUrl`) through a default-configured
  `X509ClientCertificateAuthenticationProvider` delegate, because `X509SelfSignedCertificateVerifier` is package-private
  (Task 1 correction, see "Verified in Task 1").
- **jti replay**: Spring Authorization Server 7.1.2 neither requires `jti` nor keeps a replay store (verified in
  `JwtClientAssertionDecoderFactory`, Task 1 correction: the plan first said presence was checked). A `V800` table keyed `(client_id, jti)` with `expires_at`, an insert that
  reports whether the row was new (`ON CONFLICT DO NOTHING`), a validator added through
  `setJwtValidatorFactory`, and a scheduled purge. Assertion lifetime capped by `authserver.client-assertion.max-lifetime`
  (default `PT5M`).
- **Implicit errors**: the authorization endpoint's error handler is a single slot already owned by the MFA customizer,
  and the response handler is a single slot too. So errors before the client and redirect URI are validated are thrown
  (no redirect, the existing handler answers `400`), and errors after it (missing `state`, bad scope, consent needed)
  are returned by the provider as an authenticated `LegacyImplicitErrorToken` that the legacy response handler renders
  as `#error=…&state=…`. The legacy response handler delegates every non-implicit result to the framework default
  (`code` responses unchanged). The provider applies `MfaPolicy` itself (the MFA validator only covers the
  authorization-code provider), throwing `SecondFactorRequiredException` as the code flow does.
- **Public client without PKCE**: `ClientRegistration` keeps "a public client must require PKCE", except for a client
  whose only grant type is `implicit` (PKCE has no meaning without a code). The implicit client never requires consent
  (the consent POST only issues codes); a registration with `implicit` and `requireConsent` is refused.
- **Demo client seeding**: under `legacy-implicit` only, `LegacyImplicitClientSeeder` upserts `legacy-implicit-spa`
  from `authserver.legacy-implicit.*` (redirect URI, scopes, audience, lifetime) like `ClientSeeder`; the static page is
  served by a profile-only resource handler from `classpath:/legacy-implicit/` (not `static/`, so nothing is exposed
  without the profile). It is part of the opt-in feature, not demo-only code in a test sense, and its Javadoc says why.
- **service-client becomes hexagonal** (CLAUDE.md: "single boot module until #8 gives it a domain"): `domain`,
  `application`, `infrastructure/resourceserver` (generated client + OAuth2 client wiring, the only module with
  Spring Security), `boot` (runners per profile: existing `device-flow`, new `client-credentials`, `token-exchange`),
  with enforcer bans and a `HexagonalArchitectureTest`. The device-flow package stays in `boot` unchanged.
- **Resource server mTLS/DPoP**: the JWT decoder Boot builds already includes `X509CertificateThumbprintValidator`
  (to confirm in Task 1); the resource server gains TLS only through standard `server.ssl.*` (bundle,
  `client-auth: want`) set by the tests, no code, and DPoP through `oauth2ResourceServer(...)`'s DPoP support.
- **PAR**: `authserver.par.enabled` (default `false`), not a Spring profile: profiles select adapters here, features are
  switched by properties (as `authserver.x509.enabled`).
- **Settings in one task**: every new `authserver.*` block lands in `application.yml` (tagged) in Task 5, so the
  parallel feature tasks of Group 3 never edit the same file.

Open clarifications: none

## Acceptance criteria coverage

| # | Criterion | Covered by tasks |
|---|---|---|
| 1 | "All scope items are implemented and tested." | Task 2 – Task 14 |
| 2 | "No committed keys or certificates." | Task 6, Task 10, Task 12, Task 14 |
| 3 | "`./mvnw verify` green" | Task 14 |
| 4 | "the tags are listed in the PR" | Task 14 |
| 5 | derived: `response_type=token` is rejected with `unsupported_response_type` by default and for any client but `legacy-implicit-spa`; with the profile the fragment (`access_token`, `token_type`, `expires_in`, `state`) is issued only to that client, with an exact redirect URI and `state`, no refresh token | Task 7, Task 12 |
| 6 | derived: `service-client` obtains a client-credentials token (cached, refreshed before expiry) and reads `GET /api/documents` | Task 4, Task 10, Task 12 |
| 7 | derived: `client_secret_basic`, `private_key_jwt` (registered JWK and `jwkSetUrl`, replayed `jti` refused), `tls_client_auth` (trusted CA only), `self_signed_tls_client_auth` and DPoP each work end to end against `auth-server` + `resource-server` | Task 2, Task 3, Task 6, Task 10, Task 11, Task 12 |
| 8 | derived: a certificate-bound token used without its certificate (and a DPoP-bound token without a proof) is rejected by the resource server | Task 9, Task 12 |
| 9 | derived: the exchanged token carries `act` and the downstream call is made on behalf of the user | Task 8, Task 10, Task 12 |
| 10 | derived: PAR works when enabled and is absent by default | Task 11 |

## Current code state

- **Protocol chain**: `api.web.SecurityConfig.authorizationServerSecurityFilterChain` applies every
  `api.web.ProtocolChainCustomizer` in `@Order` after OIDC: `MfaProtocolChainCustomizer` `@Order(0)` (validator of
  `OAuth2AuthorizationCodeRequestAuthenticationProvider` + `errorResponseHandler`), `StepUpProtocolChainCustomizer`
  `@Order(1)` (`authorizationRequestConverters(addFirst)`), `DeviceProtocolChainCustomizer` `ORDER = 2`
  (`clientAuthentication(converter/provider)` for public device clients), `ConsentProtocolCustomizer` `@Order(20)`,
  unordered `UserInfoConfiguration` / `DynamicClientRegistrationConfiguration`. New orders: `clientauth` 3, legacy
  implicit 4, `par` 5.
- **Device model to copy**: `api.web.implicit.DeviceConfiguration` builds `DeviceClientAuthenticationConverter` /
  `Provider` / `Token` and the guard, wired by `DeviceProtocolChainCustomizer`; tests under
  `auth-server/api/web/src/test/.../implicit/`. Only `api/web` has an `implicit` package today (no domain/application/
  persistence `implicit` package).
- **Clients**: `domain.clients.ClientRegistration` (record, 16 components; compact constructor refuses a public client
  without PKCE), port `ClientRegistrationRepository`; `infrastructure.persistence.clients.RegisteredClientMapper`
  (maps `requireProofKey`, `requireConsent`, custom `settings.client.audiences` / `settings.client.mfa.required`, TTLs,
  format, reuse; **not** `jwkSetUrl`, `tokenEndpointAuthenticationSigningAlgorithm`, `x509CertificateSubjectDN`,
  `x509CertificateBoundAccessTokens`); `JdbcClientRegistrationRepository.save` rebuilds all settings on update.
  `application.clients.CreateClientUseCase` always generates a secret for a confidential client;
  `DefaultClientDefinitions` (`bff`, `spa-public`, `RESOURCE_SERVER_AUDIENCE`). Admin API `/api/admin/clients`
  (`ClientRequest` in `apis/auth-server/rest-server/auth-server-api-v1.yaml`, tag `clients-schemas`;
  `ClientAdminController`, `ClientDtoMapper`, `ClientExceptionHandler`; `ClientAdminIT`). `authMethods`/`grantTypes`
  are free strings.
- **Seeding**: `infrastructure.persistence.dev.DevDataInitializer` (`dev`: demo user, `bff`, `device-client`),
  `api.web.clients.ClientSeeder` + `ClientSeedProperties` (non-dev).
- **Tokens**: `api.web.tokens.IssuedTokenClaims` (roles/tenant except for `client_credentials`, `aud` from
  `settings.client.audiences`, then every `JwtClaimsContributor`), `RolesTenantAudienceTokenCustomizer`,
  `ReferenceTokenClaimsCustomizer`. The framework's `DefaultOAuth2TokenCustomizers` runs first and already writes
  `cnf.x5t#S256` (mTLS client + `x509CertificateBoundAccessTokens`), `cnf.jkt` (DPoP proof) and `act` (token
  exchange composite principal).
- **Framework support verified in the 7.1.2 jars** (`spring-security-oauth2-authorization-server`, configurers in
  `spring-security-config`): token exchange provider/converter (registered by default at the token endpoint);
  `JwtClientAssertionAuthenticationProvider.setJwtDecoderFactory`, `JwtClientAssertionDecoderFactory.setJwtValidatorFactory`
  (keys only from `jwkSetUrl`, no `jti` check at all, no replay store); `X509ClientCertificateAuthenticationProvider.setCertificateVerifier`
  (`Consumer<OAuth2ClientAuthenticationContext>`), `X509SelfSignedCertificateVerifier` (package-private, not reusable);
  DPoP (`DPoPProofVerifier`, package-private, called by the grant providers);
  PAR (`OAuth2PushedAuthorizationRequestEndpointConfigurer`, opt-in `pushedAuthorizationRequestEndpoint(...)`).
  **No implicit support**: `OAuth2AuthorizationEndpointFilter` converts, authenticates, then calls one success handler
  and one failure handler (converters, providers and both handlers are configurable on `authorizationEndpoint`).
- **Verified in Task 1 (read from the 7.1.2 / Boot 4.1.2 sources jars in `~/.m2`, not memory)**:
  - **Authorization endpoint** (`OAuth2AuthorizationEndpointConfigurer`): `authorizationRequestConverter(AuthenticationConverter)`
    and `authorizationRequestConverters(Consumer<List<AuthenticationConverter>>)` (added ones go first, then the consumer sees
    the defaults `OAuth2AuthorizationCodeRequestAuthenticationConverter`, `OAuth2AuthorizationConsentAuthenticationConverter`,
    wrapped in a `DelegatingAuthenticationConverter`: first non-null result wins); `authenticationProvider(...)` /
    `authenticationProviders(Consumer<List<AuthenticationProvider>>)`; `authorizationResponseHandler(AuthenticationSuccessHandler)`;
    `errorResponseHandler(AuthenticationFailureHandler)` (single slot, owned by `MfaProtocolChainCustomizer`).
    **Two filters share the converter list**: `OAuth2AuthorizationCodeRequestValidatingFilter` (added before
    `AbstractPreAuthenticatedProcessingFilter`, i.e. before the chain's `AuthorizationFilter`) converts the request and only
    validates it when the result is an `OAuth2AuthorizationCodeRequestAuthenticationToken` (any other token type passes
    through untouched to the endpoint filter, which converts again); `OAuth2AuthorizationEndpointFilter` (added after
    `AuthorizationFilter`) converts, calls `ProviderManager.authenticate`, and an `OAuth2AuthenticationException` goes to the
    error handler. The default error handler **casts** to `OAuth2AuthorizationCodeRequestAuthenticationException` and
    answers `400` (`sendError`) when its token has no redirect URI, else redirects with `?error=` (query, never fragment), so
    every error the legacy implicit code throws must be that exception type. The default converter throws
    `unsupported_response_type` (`OAuth2AuthorizationCodeRequestAuthenticationException`, no authentication, so `400`) for any
    `response_type` other than `code`; it also parses `request_uri` (PAR).
  - **Unauthenticated user**: the endpoint filter runs after `AuthorizationFilter`, so an anonymous user never reaches the
    provider: the chain's entry point redirects to login and the saved request resumes. The code provider's own check
    (`isPrincipalAuthenticated`: non-null, not `AnonymousAuthenticationToken`, `isAuthenticated()`) throws `invalid_request`
    (`principal`), or `login_required` with `prompt=none` and `openid`, only as a fallback; a legacy provider copies that
    check. The converter reads the principal from `SecurityContextHolder` (anonymous token when null).
  - **Redirect URIs** (`OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR`, public
    `Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext>`, but typed to the code token): a present URI must parse and
    have no fragment, then `registeredClient.getRedirectUris().contains(uri)` (exact string match) except loopback hosts
    (any port, otherwise equal); an absent URI is accepted only for a single registered URI and without `openid`. The legacy
    provider cannot call it (the context needs a code token), so it re-implements the exact match (no loopback exception,
    URI required).
  - **Code provider internals to mirror**: builds `OAuth2Authorization.withRegisteredClient(rc).principalName(...)
    .authorizationGrantType(...).attribute(Principal.class.getName(), principal).attribute(OAuth2AuthorizationRequest.class.getName(), req)`;
    consent decision by `authorizationConsentRequired` predicate; success result is a token carrying code, redirect URI, state
    and scopes. `OAuth2AuthenticationProviderUtils.accessToken(builder, token, ctx)` is **package-private**: a custom provider
    repeats it (`OAuth2AccessToken` of type `BEARER`, `DPOP` when `cnf.jkt`; `builder.token(accessToken, md -> md.put(
    Token.CLAIMS_METADATA_NAME, claims) / INVALIDATED_METADATA_NAME=false / OAuth2TokenFormat.class.getName()=format value))`.
  - **Custom grant type and token generation**: `AuthorizationGrantType` has only `AUTHORIZATION_CODE`, `REFRESH_TOKEN`,
    `CLIENT_CREDENTIALS`, `JWT_BEARER`, `DEVICE_CODE`, `TOKEN_EXCHANGE`; there is **no `IMPLICIT`** constant, use
    `new AuthorizationGrantType("implicit")` (a registered client's grant types are free strings). `DefaultOAuth2TokenContext
    .builder().registeredClient().principal().authorizationServerContext(AuthorizationServerContextHolder.getContext())
    .authorizedScopes().tokenType(OAuth2TokenType.ACCESS_TOKEN).authorizationGrantType().authorizationGrant(authentication)`
    (`authorization` optional; `put(Object,Object)` for extras, `OAuth2TokenContext.DPOP_PROOF_KEY` for a DPoP proof).
    `JwtGenerator` asserts non-null principal and grant type, uses `aud = client_id`, `sub = principal.getName()`, `exp = now +
    accessTokenTimeToLive` of the client's `TokenSettings` (so a legacy lifetime cap is the client's TTL, set when seeded),
    `scope` claim from authorized scopes, `nbf`, `jti`; only when the client's format is `SELF_CONTAINED` (otherwise
    `OAuth2AccessTokenGenerator`, `REFERENCE`). The generator bean is `OAuth2TokenGenerator` from the application context or a
    `DelegatingOAuth2TokenGenerator(JwtGenerator, OAuth2AccessTokenGenerator, OAuth2RefreshTokenGenerator)` built by the
    configurer; **the framework's `DefaultOAuth2TokenCustomizers` always runs before the application's customizer beans**
    (composition in `OAuth2ConfigurerUtils`), so `cnf` and `act` are written first and `IssuedTokenClaims` may overwrite `aud`.
    In `DefaultOAuth2TokenCustomizers`, `cnf.x5t#S256` needs `authorizationGrant.getPrincipal() instanceof
    OAuth2ClientAuthenticationToken` with method `tls_client_auth` / `self_signed_tls_client_auth` and
    `x509CertificateBoundAccessTokens`; `cnf.jkt` needs `DPOP_PROOF_KEY`; `act` is nested from
    `OAuth2TokenExchangeCompositeAuthenticationToken.getActors()` (each `iss`, `sub` of the actor's access token).
  - **Token exchange** (`OAuth2TokenExchangeAuthenticationProvider`, registered by default at the token endpoint; converter
    `OAuth2TokenExchangeAuthenticationConverter`): client must have grant `urn:ietf:params:oauth:grant-type:token-exchange`
    (else `unauthorized_client`); a `jwt` requested token type needs a `SELF_CONTAINED` client. Subject and actor tokens are
    looked up with `OAuth2AuthorizationService.findByToken(token, ACCESS_TOKEN)` (so they must be access tokens this server
    issued and stored, active, and the subject's authorization must hold a `Principal` attribute, else `invalid_grant`); the token
    type parameter must be `urn:ietf:params:oauth:token-type:access_token`, or `...:jwt` for a self-contained one. **`may_act`**:
    read from the subject token's claims; when present, an `actor_token` is mandatory and its `iss` and `sub` must equal
    `may_act`'s (else `invalid_grant`); when absent, any actor token is accepted (and the actor token may be omitted).
    **`audience` and `resource` are parsed (resource must be a URI) and kept on `OAuth2TokenExchangeAuthenticationToken`
    but the provider ignores them**: the issued token's `aud` is the exchanging client's id from `JwtGenerator` and then whatever
    `IssuedTokenClaims` writes from `settings.client.audiences`. Scopes: requested ones (or the subject's) must all be in the
    exchanging client's registered scopes (`invalid_scope`). The principal in the token context is the subject's stored principal,
    or an `OAuth2TokenExchangeCompositeAuthenticationToken(subject, actors)` when an actor token was given: its authorities and
    `getPrincipal()` are the subject's, so `getName()` is the user's name and `IssuedTokenClaims` computes `roles`/`tenant`
    for the user (grant type is not `CLIENT_CREDENTIALS`), never the actor's; `act` is added by the framework. No refresh
    token; DPoP proof honoured (`DPoPProofVerifier.verifyIfAvailable`, `cnf.jkt`). The composite token and
    `OAuth2TokenExchangeActor` have Jackson mixins in `OAuth2AuthorizationServerJacksonModule`, which
    `SecurityJacksonModules.getModules` (used by `AuthorizationJsonMapperFactory`) adds when the authorization server is on the
    classpath, so the stored principal round-trips without a new contributor.
  - **Client authentication**: `OAuth2ClientAuthenticationContext.with(OAuth2ClientAuthenticationToken).registeredClient(rc)
    .build()` (`getRegisteredClient()`, `getAuthentication()`; credentials of an mTLS token are the `X509Certificate[]`).
    `JwtClientAssertionDecoderFactory.DEFAULT_JWT_VALIDATOR_FACTORY` checks `iss == sub == client_id`, `aud` containing the issuer or
    the token, introspection, revocation or **PAR** endpoint URL, `exp` present and timestamps; **no `jti` check and no `iat`
    requirement**, so the replay validator must itself require `jti` (and `iat`, or derive the lifetime from `now` when absent).
    The factory caches one `JwtDecoder` per `registeredClient.getId()` forever and needs `tokenEndpointAuthenticationSigningAlgorithm`
    plus `jwkSetUrl` (or `client_secret_jwt` HMAC); the custom factory therefore caches by client id and a hash of the
    stored JWKs (Task 6.1 already says so) and never lets the framework one see a registered-JWK client.
    `X509ClientCertificateAuthenticationProvider(RegisteredClientRepository, OAuth2AuthorizationService)`: `setCertificateVerifier`
    **replaces** the default verifier entirely (default: `tls_client_auth` compares
    `cert.getSubjectX500Principal().getName()` with `ClientSettings.getX509CertificateSubjectDN()`; self-signed requires issuer ==
    subject and the leaf public key equal to an `x5c` key of the `jwkSetUrl` set). `X509SelfSignedCertificateVerifier` is
    **package-private** and the private DN check is not exposed: our verifier repeats the DN comparison (trivial) and, for the
    `jwkSetUrl` fallback, calls `authenticate(token)` on a second, default-configured provider instance (its result is
    discarded; it throws `invalid_client` on mismatch).
  - **PAR**: `OAuth2AuthorizationServerConfigurer.pushedAuthorizationRequestEndpoint(Customizer<OAuth2PushedAuthorizationRequestEndpointConfigurer>)`;
    default path `/oauth2/par` (`AuthorizationServerSettings.getPushedAuthorizationRequestEndpoint`); the code provider consumes
    `request_uri` once and the validating filter lets a `request_uri` request through to the provider.
  - **Resource server DPoP**: `http.oauth2ResourceServer(o -> o.jwt(...).dPoP(Customizer.withDefaults()))` (`DPoPConfigurer`:
    `requestMatcher`, `authenticationConverter`, `authenticationSuccessHandler`, `authenticationFailureHandler`; DSL in
    `OAuth2ResourceServerDsl`/`DPoPDsl`); it adds an `AuthenticationFilter` matching `Authorization: DPoP ...`, a
    `DPoPAuthenticationProvider` (authenticates the JWT through the chain's manager, then verifies the proof with
    `DPoPProofJwtDecoderFactory`: `typ dpop+jwt`, embedded public `jwk`, `htm`, `htu` equal to `getRequestURL()` (so a proxy
    that changes scheme/host breaks it), `iat` within 30 s, `ath`, thumbprint equal to `cnf.jkt`, and a **per-instance in-memory
    replay cache** keyed by `jti`; `setDPoPProofVerifierFactory` swaps it). **`BearerTokenAuthenticationFilter` already rejects a
    token whose `cnf` has `jkt` when it arrives as `Bearer`** (`invalid_token`), so the downgrade test needs no code. Client side
    of the token endpoint: the DPoP proof is the `DPoP` request header, validated by the converters of auth code, client
    credentials, refresh, device code and token exchange; the response has `token_type: DPoP`, which
    `DefaultMapOAuth2AccessTokenResponseConverter` maps to `OAuth2AccessToken.TokenType.DPOP`.
  - **mTLS at the resource server**: `JwtValidators.createDefault()` / `createDefaultWithValidators(...)` always include the
    package-private `X509CertificateThumbprintValidator` (index 0, reads the request attribute
    `jakarta.servlet.request.X509Certificate`, fails with `invalid_token` when a token has `cnf.x5t#S256` and no certificate or a
    different one). **Boot 4.1.2's `JwtDecoderConfiguration` (`spring-boot-security-oauth2-resource-server`) builds its validator
    with `JwtValidators.createDefault()` or `createDefaultWithValidators(issuer, audience, extra `OAuth2TokenValidator<Jwt>` beans)`
    for the public-key, `jwk-set-uri` and `issuer-uri` decoders**, so the thumbprint validator is already there and Task 9.1's
    fallback decoder is not needed; any hand-declared `JwtDecoder` must use `JwtValidators.createDefaultWithValidators` to keep
    it. The attribute is set by Tomcat for `server.ssl.client-auth: want|need` when a certificate is presented.
  - **Client side (`spring-security-oauth2-client` 7.1.2)**: `RestClientClientCredentialsTokenResponseClient` and
    `RestClientTokenExchangeTokenResponseClient` extend `AbstractRestClientOAuth2AccessTokenResponseClient` (`setRestClient`,
    `setHeadersConverter`, `addHeadersConverter`, `setParametersConverter`, `addParametersConverter`, `setParametersCustomizer`);
    by default only `client_secret_basic`, `client_secret_post` and `none` pass the method check, but **any call to a
    `set/add*Converter` method removes the check**, so `private_key_jwt` is `addParametersConverter(new
    NimbusJwtClientAuthenticationParametersConverter<>(registration -> jwk))` (adds `client_assertion_type` and `client_assertion`;
    claims `iss=sub=client_id`, `aud` = the registration's token URI, `jti` random, 60 s lifetime, no `iat` customisation needed:
    `iat` and `exp` are set; algorithm from the JWK `alg`, else RS256/ES256; `setJwtClientAssertionCustomizer` available) and
    mTLS is a `RestClient` built over the SSL bundle set with `setRestClient(...)` (the default parameters converter then sends
    `client_id` in the body for any non-basic method; use `ClientAuthenticationMethod.TLS_CLIENT_AUTH`).
    `TokenExchangeOAuth2AuthorizedClientProvider` (registration must use `AuthorizationGrantType.TOKEN_EXCHANGE`): setters
    `setAccessTokenResponseClient`, `setSubjectTokenResolver`, `setActorTokenResolver` (both
    `Function<OAuth2AuthorizationContext, OAuth2Token>`), `setClockSkew`, `setClock`; the default subject resolver only takes a
    principal whose `getPrincipal()` is an `OAuth2Token`, so the CLI sets its own; it sends `scope` from the registration,
    `requested_token_type=access_token`, `subject_token(_type)`, `actor_token(_type)` and **no `audience`/`resource`** (add them with
    `setParametersCustomizer`, remembering the server ignores them); the authorized client is cached per `(registrationId,
    principal.getName())`, so the principal name must be the user's, never constant across users.
    `OAuth2AuthorizedClientProviderBuilder` has **no token-exchange method**: register it with `.provider(new
    TokenExchangeOAuth2AuthorizedClientProvider())` (or `DelegatingOAuth2AuthorizedClientProvider`); `clientCredentials(Consumer<
    ClientCredentialsGrantBuilder>)` offers `accessTokenResponseClient`, `clockSkew` (default 60 s: a token is renewed once
    `now > expiresAt - skew`), `clock`. `AuthorizedClientServiceOAuth2AuthorizedClientManager(ClientRegistrationRepository,
    OAuth2AuthorizedClientService)` works without a servlet request (`setAuthorizedClientProvider`, `setContextAttributesMapper`).
    `OAuth2ClientHttpRequestInterceptor(OAuth2AuthorizedClientManager)` resolves the registration id from a request attribute
    (`RequestAttributeClientRegistrationIdResolver`, `ClientRegistrationIdProcessor`/`ClientAttributes`) and the principal from
    `SecurityContextHolder` (anonymous when empty: set `RequestAttributePrincipalResolver.principal(name)` or
    `setPrincipalResolver`), and **only ever calls `headers.setBearerAuth(...)`**.
  - **Gap: no client-side DPoP anywhere in Spring Security 7.1.2** (no match for `dpop` in `spring-security-oauth2-client`).
    Nimbus `oauth2-oidc-sdk` 11.38.2 (already transitive through the client) provides `DefaultDPoPProofFactory` /
    `DPoPProofFactory.createDPoPJWT(htm, htu[, AccessToken])` (adds `ath`), to be hand-wired in two places: an
    `addHeadersConverter` on the token response clients adding `DPoP: <proof for POST token-uri>` (no `ath`), and a
    `ClientHttpRequestInterceptor` of our own, in place of `OAuth2ClientHttpRequestInterceptor`'s bearer header, that sets
    `Authorization: DPoP <token>` plus `DPoP: <proof with ath>` when the authorized client's token type is `DPOP`.
- **TLS port**: `api.web.x509` (`X509TlsConnectorCustomizer`, `authserver.x509.port`, `AnyClientCertificateTrustManager`
  accepts any chain, `DevX509KeyStore` in `dev`). The protocol chain sees the native
  `jakarta.servlet.request.X509Certificate` on that port; `ForwardedCertificateFilter` is on the login chain only.
- **service-client**: single `service-client/boot` (`ServiceClientApplication`, `web-application-type: none`,
  `serviceclient.device` = `DeviceFlowCli` `@Profile("device-flow")`, `DeviceAuthorizationClient`, …,
  `application-device-flow.yml`), deps `spring-boot-starter-jackson`, `spring-boot-starter-security-oauth2-client`;
  no enforcer bans, no `HexagonalArchitectureTest`, no client-credentials code. Model for the generated client:
  `bff/infrastructure/resourceserver` (`openapi-generator` `java`/`restclient` from
  `apis/resource-server/rest-server/resource-server-api-v1.yaml`, port `DocumentGateway`, `RestDocumentGateway`).
- **resource-server**: `GET /api/documents` (`SCOPE_documents.read`; admins get all, others `listOwn(sub)`),
  `DELETE /api/documents/{id}` (step-up); `api.web.security.SecurityConfig` (JWT chain `!opaque`, opaque chain
  `opaque`), decoder auto-configured from `issuer-uri` + `audiences`; tests `SecurityConfigIT`, `OpaqueTokenSecurityIT`,
  `StepUpDeletionIT`, `TestTokens`.
- **Tests**: `test-support` `TestPki` (`create`, `issueServer`, `issueClient`, `issueExpiredClient`, `clientContext`),
  `TestCertificates`, `@PostgresIT`; auth-server `TokenFlowIT` (client credentials), `AuthServerFixtures`,
  `X509TlsLoginIT`; `e2e-tests` `ManagedApp`, `RunningAuthServer` (dev profile, extra args, `sql(...)`),
  `ResourceServerEndToEndIT` (`copyClient` inserts client rows by SQL), `DeviceFlowEndToEndIT` (runs the
  service-client jar). **No test asserts that `response_type=token` is rejected.**
- **Precedent**: `.archive/implementation_plan_7.md` (verify-first task, `ProtocolChainCustomizer` wiring, run-time PKI,
  packaged service-client jar in e2e).
- **Docs**: `docs/modules/ROOT/pages/` (`clients.adoc`, `resource-server.adoc`, `device-grant.adoc`, `reference.adoc`…),
  `docs/antora.yml` (one scan per module), `apis/README.md`, CLAUDE.md feature list.

## Implementation steps

### Group 1 – Verify the framework (Parallelizable: yes)

- [x] Task 1. Verify the remaining Spring Security 7.1.2 APIs and record them here _(java-springboot)_
  - [x] Task 1.1. Read the sources jars in `~/.m2` (not memory) for: `OAuth2AuthorizationEndpointConfigurer`
    (`authorizationRequestConverters`, `authenticationProviders`, `authorizationResponseHandler`, how an unauthenticated
    principal is sent to login), `OAuth2AuthorizationCodeRequestAuthenticationProvider` (how it builds the authorization
    and checks redirect URIs, to reuse the same exact-match rule), `OAuth2TokenGenerator` /
    `DefaultOAuth2TokenContext` for a custom grant type; `OAuth2TokenExchangeAuthenticationProvider` (subject/actor
    token lookup, `may_act`, audience/resource parameters, what `IssuedTokenClaims` sees as principal);
    `OAuth2ClientAuthenticationContext`; `DPoPProofVerifier` and the resource-server DPoP DSL; Boot 4.1.2's
    `OAuth2ResourceServerJwtConfiguration` (does its decoder include `X509CertificateThumbprintValidator`?);
    `TokenExchangeOAuth2AuthorizedClientProvider`, `NimbusJwtClientAuthenticationParametersConverter`,
    `RestClientClientCredentialsTokenResponseClient`, `OAuth2ClientHttpRequestInterceptor`, and whether Spring Security
    7.1 offers client-side DPoP for `RestClient` (else a Nimbus `DPoPProofFactory` is hand-wired)
  - [x] Task 1.2. Write the confirmed signatures, defaults and gaps under "Current code state"; adjust later tasks if a
    fact contradicts a choice above (record why). No source change.
    Done: facts under "Verified in Task 1" in Current code state. Adjustments (why): Task 6.1 (framework requires neither
    `jti` nor `iat`), Task 6.2 (`X509SelfSignedCertificateVerifier` is package-private; `setCertificateVerifier` replaces the
    default DN check), Task 8.1/8.2 (provider ignores `audience`/`resource`; composite principal needs no roles contributor),
    Task 9.1 (Boot decoder already has the thumbprint validator; DPoP-as-Bearer already rejected), Task 10.2 (builder has no
    token-exchange method; no client-side DPoP in Spring, hand-wired with Nimbus). No source file touched, no tests, no
    license headers needed.

### Group 2 – Model, persistence, settings and service-client skeleton (Parallelizable: yes — the four tasks touch disjoint files: `clients` packages, `clientauth` + `V800`, `application*.yml`, `service-client/**`)

- [x] Task 2. Client settings for the new authentication methods _(java-springboot)_
  - [x] Task 2.1. `domain.clients.ClientRegistration`: add `jwkSetUrl` (nullable), `jwks` (nullable public JWK set JSON),
    `tokenEndpointSigningAlgorithm` (nullable), `tlsClientAuthSubjectDn` (nullable), `certificateBoundAccessTokens`
    (boolean); relax the PKCE invariant only when `grantTypes.equals(List.of("implicit"))`; refuse `implicit` together
    with `requireConsent`, with refresh token, or with a confidential client; refuse `tls_client_auth` without a subject
    DN, `self_signed_tls_client_auth` / `private_key_jwt` without `jwks` or `jwkSetUrl`. Update every constructor call
    (use cases, tests, `DefaultClientDefinitions`, `DevDataInitializer`, `ClientSeeder`). Unit tests for each rule.
    _Done: auth-server domain/application/persistence/api-web/boot tests: ClientRegistration + every constructor call; ClientRegistrationTest; group validation done: full `./mvnw clean verify` green incl. ITs and all gates._
  - [x] Task 2.2. `RegisteredClientMapper` (both directions): `ClientSettings.jwkSetUrl`,
    `tokenEndpointAuthenticationSigningAlgorithm`, `x509CertificateSubjectDN`, custom `settings.client.jwks`;
    `TokenSettings.x509CertificateBoundAccessTokens`. Unit tests, including an update round trip through
    `JdbcClientRegistrationRepository` (existing IT extended) proving no setting is lost.
    _Done: RegisteredClientMapper (+ unit tests, JdbcClientRegistrationRepositoryIT extended, not run); group validation done: full `./mvnw clean verify` green incl. ITs and all gates._
  - [x] Task 2.3. `CreateClientUseCase` / `RotateClientSecret…`: generate a secret only when an auth method is a
    `client_secret_*` one; a `private_key_jwt`/mTLS-only client gets none (response `clientSecret` null). Tests.
    _Done: CreateClientUseCase/RotateClientSecretUseCase use ClientRegistration.usesClientSecret(); unit tests; group validation done: full `./mvnw clean verify` green incl. ITs and all gates._
  - [x] Task 2.4. Contract first: `ClientRequest` / `ClientResponse` gain `jwkSetUrl` (uri), `jwks` (object, public keys
    only), `tokenEndpointAuthSigningAlgorithm` (enum `RS256`, `ES256`, `PS256`…), `tlsClientAuthSubjectDn`,
    `certificateBoundAccessTokens`; document the accepted `authMethods` / `grantTypes` values. Regenerate, then
    `ClientDtoMapper` plus a `ClientJwksParser` `@Component` in `api.web.clients` (Nimbus `JWKSet.parse`; a key with
    private material is `InvalidClientJwksException` → `400 invalid-jwks` in `ClientExceptionHandler`). Extend
    `ClientAdminIT`; tag `clients-auth-settings`.
    _Done: contract (tag clients-auth-settings), ClientDtoMapper, ClientJwksParser, InvalidClientJwksException, ClientExceptionHandler, ClientAdminIT extended (not run); group validation done: full `./mvnw clean verify` green incl. ITs and all gates._
- [x] Task 3. Client-assertion `jti` replay store (`clientauth`) _(java-springboot)_ — auth-server domain, application and infrastructure/persistence; unit tests added; `JdbcClientAssertionReplayRegistryIT` written, not run; group validation done: full `./mvnw clean verify` green incl. ITs and all gates.
  - [x] Task 3.1. `V800__client_assertion_jtis.sql` (`client_id`, `jti`, `expires_at timestamptz`, PK `(client_id, jti)`,
    index on `expires_at`; tag `client-assertion-schema`).
  - [x] Task 3.2. `domain.clientauth`: port `ClientAssertionReplayRegistry` (`boolean register(String clientId, String jti,
    Instant expiresAt)` true only for a first use; `int purgeExpired(Instant now)`), value `ClientAssertionUse` with
    validation; unit tests.
  - [x] Task 3.3. `application.clientauth`: `RegisterClientAssertionUseCase` (`@Transactional`) and
    `PurgeClientAssertionsUseCase`; `ClientAssertionProperties` (`authserver.client-assertion.max-lifetime`,
    `cleanup.cron`; validated record). Mockito tests.
  - [x] Task 3.4. `infrastructure.persistence.clientauth.JdbcClientAssertionReplayRegistry`
    (`INSERT … ON CONFLICT DO NOTHING`, rows affected = 1); `@PostgresIT` test including two concurrent registrations of
    the same `jti` (exactly one wins). Add `package-info.java` to each new `clientauth` package.
- [x] Task 4. service-client hexagonal skeleton _(java-springboot)_ (note: the two use cases are `@Lazy` until Group 3 adds the gateway adapters, remove then; `ServiceClientApplicationIT` mocks the ports meanwhile)
  - [x] Task 4.1. (done: service-client/domain and service-client/application, unit tests added; group validation done: full `./mvnw clean verify` green incl. ITs and all gates) Modules `service-client/domain` (`service-client-domain`: record `Document(id, owner, title)`, ports
    `DocumentGateway` (`List<Document> listDocuments()`), `OnBehalfOfDocumentGateway`
    (`List<Document> listDocumentsAs(String subjectToken)`), exception `DocumentAccessException`) and
    `service-client/application` (`ListDocumentsUseCase`, `ListDocumentsOnBehalfOfUseCase`; no transactions, as in
    `bff`). Unit tests.
  - [x] Task 4.2. (done: service-client, domain, application, boot, root dependencyManagement, coverage and docs/antora.yml; group validation done: full `./mvnw clean verify` green incl. ITs and all gates) Poms: register modules in `service-client/pom.xml`, enforcer `bannedDependencies` per module like
    `bff`, `boot` depends on them; update the aggregator description. Add the modules to `coverage/pom.xml` and one scan
    each to `docs/antora.yml`.
  - [x] Task 4.3. (done: HexagonalArchitectureTest, 15 rules green; group validation done: full `./mvnw clean verify` green incl. ITs and all gates) `service-client/boot/src/test/.../HexagonalArchitectureTest` (copied rules from `bff`, root
    `com.irurueta.authserver.serviceclient`); the `device` package stays a boot-level CLI and is allowed explicitly.
- [x] Task 5. Settings blocks (`auth-server/boot/src/main/resources`) _(java-springboot)_
  - [x] Task 5.1. (auth-server/boot application.yml; group validation done: full `./mvnw clean verify` green incl. ITs and all gates) `application.yml`: tagged blocks `client-assertion-config` (`authserver.client-assertion.*`),
    `mtls-config` (`authserver.mtls.trusted-authorities: []`), `par-config` (`authserver.par.enabled: false`).
  - [x] Task 5.2. (auth-server/boot application-legacy-implicit.yml; group validation done: full `./mvnw clean verify` green incl. ITs and all gates) New `application-legacy-implicit.yml` (tag `legacy-implicit-config`): `authserver.legacy-implicit.client-id:
    legacy-implicit-spa`, `redirect-uri` (`${AUTHSERVER_LEGACY_IMPLICIT_REDIRECT_URI:http://localhost:9000/legacy-implicit/}`),
    `scopes: documents.read`, `audience: resource-server`, `access-token-ttl: PT5M` (max `PT15M`). Comment that the
    profile is a legacy demo and must never be enabled in production.

### Group 3 – auth-server protocol features and service-client adapter (Parallelizable: yes — each task owns its feature package, its `ProtocolChainCustomizer` order and its own test classes; none edits `AuthServerFixtures` (each adds its own helper))

- [x] Task 6. Client authentication: private_key_jwt and mTLS (`api.web.clientauth`) _(java-springboot)_ — api/web `clientauth` package; unit tests added and green; group validation done: full `./mvnw verify` (all modules but e2e-tests) green incl. ITs, gates and 80%/70% JaCoCo (aggregate 99.1% line, 97.6% branch).
  - [x] Task 6.1. `ReplayRejectingJwtValidator` (`OAuth2TokenValidator<Jwt>`: `jti` and `iat` required (the framework requires
    neither, Task 1), `exp - iat` ≤ max lifetime,
    `RegisterClientAssertionUseCase` true) and `RegisteredJwksClientAssertionDecoderFactory`
    (`JwtDecoderFactory<RegisteredClient>`: `settings.client.jwks` → `NimbusJwtDecoder.withJwkSource(ImmutableJWKSet)` with
    the framework's default assertion validators + replay validator; else the framework factory with
    `setJwtValidatorFactory(default.andThen(replay))`; cached per client id + settings hash with Caffeine).
  - [x] Task 6.2. `MtlsProperties` (`authserver.mtls.trusted-authorities`, PEM paths, validated, loaded once) and
    `ClientCertificateVerifier` (`Consumer<OAuth2ClientAuthenticationContext>`): `tls_client_auth` → PKIX path validation
    against the trusted anchors (`CertPathValidator`, revocation disabled, documented), refused when none configured,
    then our own DN check (`getSubjectX500Principal().getName()` equals `getX509CertificateSubjectDN()`); `self_signed_tls_client_auth` → the leaf's public key matches an `x5c` key of
    `settings.client.jwks`, else delegate to a default-configured `X509ClientCertificateAuthenticationProvider` instance
    (`X509SelfSignedCertificateVerifier` is package-private, Task 1); the `tls_client_auth` branch repeats the framework's
    subject-DN comparison itself because `setCertificateVerifier` replaces the default verifier.
  - [x] Task 6.3. `ClientAuthConfiguration` declaring an `@Order(3)` `ProtocolChainCustomizer`
    (`server.clientAuthentication(c -> c.authenticationProviders(...))` setting the decoder factory on
    `JwtClientAssertionAuthenticationProvider` and the verifier on `X509ClientCertificateAuthenticationProvider`), the
    authorization-server metadata `mtls_endpoint_aliases` (RFC 8705) when `authserver.x509.port` is set, and
    `ClientAssertionCleanupJob` (`@Scheduled`, cron from properties). Tags `clientauth-assertion-decoder`,
    `clientauth-certificate-verifier`, `clientauth-chain`.
  - [x] Task 6.4. Unit tests per class; `@PostgresIT` `ClientAuthenticationIT` (RANDOM_PORT, TLS port from `TestPki`):
    `client_secret_basic`; `private_key_jwt` with registered JWKs and with `jwkSetUrl` (WireMock serves the JWKS),
    replayed `jti` → `invalid_client`, over-long assertion refused; `tls_client_auth` with a CA-issued certificate
    (accepted) and a self-issued one with the same DN (refused); `self_signed_tls_client_auth`; issued token has
    `cnf.x5t#S256` equal to the certificate thumbprint when `certificateBoundAccessTokens`; DPoP proof at the token
    endpoint gives `token_type=DPoP` and `cnf.jkt`. All keys and certificates generated in the test.
- [x] Task 7. Legacy implicit flow (`api.web.implicit`, profile `legacy-implicit`) _(java-springboot)_ — done in auth-server/api/web (`implicit` package), unit tests green (49), ITs compiled not run; group validation done: full `./mvnw verify` (all modules but e2e-tests) green incl. ITs, gates and 80%/70% JaCoCo (aggregate 99.1% line, 97.6% branch).
  - [x] Task 7.1. `LegacyImplicitProperties` (validated record bound to `authserver.legacy-implicit.*`).
  - [x] Task 7.2. `LegacyImplicitAuthorizationRequestConverter` (`AuthenticationConverter`): `null` unless GET
    `/oauth2/authorize` with `response_type=token`; throws `OAuth2AuthorizationCodeRequestAuthenticationException`
    `unsupported_response_type` with no redirect for any other client id; else a `LegacyImplicitAuthorizationRequestToken`
    (client id, redirect URI, scopes, state, principal). Tag `implicit-converter`.
  - [x] Task 7.3. `LegacyImplicitAuthenticationProvider`: client exists and has grant `implicit`; redirect URI is
    present and exactly registered (else thrown, no redirect); principal authenticated (else the same path the code
    provider uses to send to login, per Task 1); `MfaPolicy` satisfied (else `SecondFactorRequiredException`);
    `state` present and scopes allowed (else `LegacyImplicitErrorToken`); issues an access token through the
    `OAuth2TokenGenerator` (`ACCESS_TOKEN`, grant `implicit`, lifetime = min(client TTL, property)), saves an
    `OAuth2Authorization` without refresh token, returns `LegacyImplicitAccessTokenToken`. Tag `implicit-provider`.
  - [x] Task 7.4. `LegacyImplicitResponseHandler` (`AuthenticationSuccessHandler`): for the two legacy tokens, `302` to
    `redirect_uri#access_token=…&token_type=Bearer&expires_in=…&scope=…&state=…` (or `#error=…&state=…`), values
    URL-encoded, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`; any other result delegated to the
    framework's default handler. Tag `implicit-response-handler`.
  - [x] Task 7.5. `LegacyImplicitConfiguration` (`@Profile("legacy-implicit")`): `@Order(4)` `ProtocolChainCustomizer`
    (`authorizationEndpoint(e -> e.authorizationRequestConverters(addFirst).authenticationProviders(add(0))
    .authorizationResponseHandler(handler))`), `LegacyImplicitClientSeeder`, a `WebMvcConfigurer` serving
    `classpath:/legacy-implicit/` at `/legacy-implicit/**`, and a `LoginChainCustomizer` (`@Order(8)`) permitting it.
    Tag `implicit-chain`.
  - [x] Task 7.6. `auth-server/api/web/src/main/resources/legacy-implicit/index.html` + `legacy-implicit.js`: builds the
    authorize URL with a random `state` (kept in `sessionStorage`), reads the fragment, checks `state`, clears the
    fragment with `history.replaceState`, shows the token's claims; no inline script (CSP friendly); Apache header.
    Tag `implicit-demo-page`.
  - [x] Task 7.7. Unit tests per class; `ImplicitRejectedIT` (default profiles: `response_type=token` → `400`
    `unsupported_response_type` for `spa-public` and an unknown response type); `LegacyImplicitIT`
    (`@ActiveProfiles({"test", "legacy-implicit"})`): fragment for `legacy-implicit-spa` (token audience `resource-server`,
    `expires_in` ≤ 300, no refresh token, introspectable), refused for `spa-public`, wrong redirect URI → no redirect,
    missing `state` → `#error=invalid_request`, `response_type=code` still works for `bff`, demo page served only
    with the profile.
- [x] Task 8. Token exchange server side (`api.web.exchange`) _(java-springboot)_
  - [x] Task 8.1. _(auth-server api/web `exchange.TokenExchangeAudienceContributor` + `TokenExchangeAudienceContributorTest`, application `DefaultClientDefinitions.TOKEN_EXCHANGE_GRANT`; group validation done: full `./mvnw verify` (all modules but e2e-tests) green incl. ITs, gates and 80%/70% JaCoCo (aggregate 99.1% line, 97.6% branch))_ Task 1 confirmed the provider is active by default and `IssuedTokenClaims` reads the composite principal
    correctly (subject's authorities and name), so no roles/tenant contributor is needed. The provider ignores the
    `audience`/`resource` parameters: add `TokenExchangeAudienceContributor` (`JwtClaimsContributor`, `@Order(120)`, only for
    grant type token-exchange) that, when the request carries `audience`, keeps only the requested audiences that are in the
    client's `settings.client.audiences` (else `invalid_target` is not available from a contributor, so an audience outside
    the client's list is simply not granted and the client's audiences stay), reading them from
    `OAuth2TokenExchangeAuthenticationToken.getAudiences()` of `context.getAuthorizationGrant()`. Add `DefaultClientDefinitions` constant
    `TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"`.
  - [x] Task 8.2. _(boot `TokenExchangeIT` written, test-compile only; group validation done: full `./mvnw verify` (all modules but e2e-tests) green incl. ITs, gates and 80%/70% JaCoCo (aggregate 99.1% line, 97.6% branch))_ `TokenExchangeIT` (`@PostgresIT`): a user token (auth-code + PKCE via fixtures helper of its own)
    exchanged by a confidential client with `subject_token` + `actor_token`, `audience=resource-server` (the client's
    `settings.client.audiences` also holds it): response
    `issued_token_type` access token, JWT `sub` = user, `act.sub` = client id, `aud` = `resource-server`; refused for a
    client without the grant, for a foreign subject token and when `may_act` (if present) excludes the actor.
    Tag `exchange-claims` if a contributor is added.
- [x] Task 9. Resource server: certificate-bound and DPoP-bound tokens _(java-springboot)_ (resource-server api/web + boot; group validation done: full `./mvnw verify` (all modules but e2e-tests) green incl. ITs, gates and 80%/70% JaCoCo (aggregate 99.1% line, 97.6% branch))
  - [x] Task 9.1. `resource-server/api/web/.../security/SecurityConfig`: enable DPoP on the JWT chain (DSL per Task 1),
    keep bearer working (a DPoP-bound token sent as `Bearer` is already rejected by the framework). Task 1 confirmed Boot's
    decoder includes `X509CertificateThumbprintValidator` (via `JwtValidators`), so no `JwtDecoder` bean is declared. Tag `resource-server-bound-tokens`.
  - [x] Task 9.2. `resource-server/boot` ITs: `BoundTokenIT` with `server.ssl` bundle (`TestPki` server + trust store,
    `client-auth: want`): a `cnf.x5t#S256` token over TLS with the matching certificate → `200`, without a certificate
    or with another one → `401`; a DPoP-bound token with a valid proof → `200`, sent as `Bearer` or without proof →
    `401`. Tokens built with the existing `TestTokens` helper (extended, not duplicated).
- [x] Task 10. service-client resource-server adapter and runners _(java-springboot)_
  - [x] Task 10.1. `service-client/infrastructure/resourceserver` module: generated `restclient` client from the
    resource-server contract (as `bff`), `RestDocumentGateway` / `RestOnBehalfOfDocumentGateway` mapping
    `DocumentResponse` through `DocumentMapper`, every failure → `DocumentAccessException`. Tag `service-client-gateway`. (service-client/infrastructure/resourceserver: pom, DocumentMapper, DocumentCalls, RestDocumentGateway, RestOnBehalfOfDocumentGateway, DocumentsApis, OnBehalfOfDocumentsApis; unit tests added; group validation done: full `./mvnw verify` (all modules but e2e-tests) green incl. ITs, gates and 80%/70% JaCoCo (aggregate 99.1% line, 97.6% branch))
  - [x] Task 10.2. `OAuth2ClientConfiguration`: `ClientRegistrationRepository` from properties
    (`service-client.auth.method`: `client_secret_basic` | `private_key_jwt` | `tls_client_auth` |
    `self_signed_tls_client_auth`), `AuthorizedClientServiceOAuth2AuthorizedClientManager` with
    `ClientCredentialsOAuth2AuthorizedClientProvider` (registered with `clientCredentials(c -> ...)`, and
    `TokenExchangeOAuth2AuthorizedClientProvider` through `.provider(...)` since the builder has no token-exchange method;
    `clockSkew` = `service-client.auth.refresh-before`, default `PT60S`,
    so the cached token is renewed before expiry) and the token-exchange provider
    (subject token from the request attribute, actor token = the client-credentials token, principal name = the user's;
    the interceptor needs a `PrincipalResolver` as there is no `SecurityContext` in the CLI); token response clients:
    `NimbusJwtClientAuthenticationParametersConverter` for `private_key_jwt` (key from `ServiceClientKeyProperties`,
    PKCS#8 PEM path or `SERVICE_CLIENT_PRIVATE_KEY`), an SSL-bundle `RestClient` for mTLS, a DPoP proof
    (`service-client.auth.dpop: true`, hand-wired with Nimbus `DefaultDPoPProofFactory`: Spring has no client-side DPoP, so
    an `addHeadersConverter` for the token request and an own interceptor setting `Authorization: DPoP` plus the proof with
    `ath` replace `OAuth2ClientHttpRequestInterceptor` when enabled); `RestClient` with
    `OAuth2ClientHttpRequestInterceptor` otherwise. Tags `client-credentials-manager`, `token-exchange-client`,
    `private-key-jwt-client`, `dpop-client`. (OAuth2ClientConfiguration, TokenEndpointClients, PrivateKeyJwkResolver, DPoPProofs, DPoPClientHttpRequestInterceptor, ResourceServerInterceptors, SslRequestFactories, PrincipalMapper, ServiceClientRegistrationMapper, properties; unit tests added; group validation done: full `./mvnw verify` (all modules but e2e-tests) green incl. ITs, gates and 80%/70% JaCoCo (aggregate 99.1% line, 97.6% branch))
  - [x] Task 10.3. `service-client/boot`: `ClientCredentialsCli` (`@Profile("client-credentials")`, prints the documents
    as JSON lines and, with `print-access-token`, the token) and `TokenExchangeCli` (`@Profile("token-exchange")`,
    subject token from `SERVICE_CLIENT_SUBJECT_TOKEN`); `application-client-credentials.yml`,
    `application-token-exchange.yml`. Hand-written main-class runners in `src/main` because the e2e test runs the jar
    (Javadoc says so). (service-client/boot: ClientCredentialsCli, TokenExchangeCli, CliConfiguration, CliProperties, CliOutput, application-client-credentials.yml, application-token-exchange.yml; unit tests added; group validation done: full `./mvnw verify` (all modules but e2e-tests) green incl. ITs, gates and 80%/70% JaCoCo (aggregate 99.1% line, 97.6% branch))
  - [x] Task 10.4. Unit tests per class (Mockito; WireMock for the token endpoint and resource server in an
    `infrastructure` IT): token reused while valid and refreshed within the skew window; assertion signed with the
    configured key; exchange sends `subject_token`/`actor_token`; `ServiceClientApplicationIT` per profile. (unit tests per class, ResourceServerAdapterIT with WireMock and ServiceClientApplicationIT per profile written, not run; group validation done: full `./mvnw verify` (all modules but e2e-tests) green incl. ITs, gates and 80%/70% JaCoCo (aggregate 99.1% line, 97.6% branch))
- [x] Task 11. PAR opt-in (`api.web.par`) _(java-springboot)_
  - [x] Task 11.1. _(api/web `par.ParConfiguration` + `ParConfigurationTest`; group validation done: full `./mvnw verify` (all modules but e2e-tests) green incl. ITs, gates and 80%/70% JaCoCo (aggregate 99.1% line, 97.6% branch))_ `ParConfiguration` (`@ConditionalOnProperty("authserver.par.enabled")`) with an `@Order(5)`
    `ProtocolChainCustomizer` (`pushedAuthorizationRequestEndpoint(withDefaults())`). Tag `par-chain`.
  - [x] Task 11.2. _(boot `ParIT` written, test-compile only; group validation done: full `./mvnw verify` (all modules but e2e-tests) green incl. ITs, gates and 80%/70% JaCoCo (aggregate 99.1% line, 97.6% branch))_ `ParIT`: disabled → `/oauth2/par` not found and absent from metadata; enabled → `201` with
    `request_uri`, authorize with `request_uri` completes the code flow (MFA still enforced), a reused `request_uri`
    refused.

### Group 4 – End-to-end tests (Parallelizable: yes)

- [x] Task 12. `e2e-tests` against the packaged jars _(java-springboot)_ (e2e-tests only: ManagedApp.output(), RunningResourceServer, ServiceClientRun, ClientAdminApi, UserTokenFlow, PublicJwks, JwtClaims, ClientCredentialsEndToEndIT (5), TokenExchangeEndToEndIT (2), LegacyImplicitEndToEndIT (2), all run and green; checkstyle green; group validation done: e2e-tests verify green (24 ITs, 5+2+2 new), checkstyle/PMD/SpotBugs green, no production change)
  - [x] Task 12.1. Helpers: `RunningResourceServer` (optionally TLS from `TestPki`, `client-auth: want`) and
    `ServiceClientRun` (runs the service-client jar with a profile, args and env, returns output and exit code); clients
    inserted through the admin API or `copyClient`-style SQL.
  - [x] Task 12.2. `ClientCredentialsEndToEndIT`: one test per method (`client_secret_basic`, `private_key_jwt` with a
    run-time key pair, `tls_client_auth` with a `TestPki` CA configured in `authserver.mtls.trusted-authorities`,
    `self_signed_tls_client_auth`, DPoP): service-client reads `/api/documents`. The certificate-bound token printed
    by the run, replayed with plain `HttpClient` without a certificate → `401`.
  - [x] Task 12.3. `TokenExchangeEndToEndIT`: Playwright signs the demo user in through `bff`'s login flow (or a direct
    PKCE client) to obtain a user token, service-client `token-exchange` run lists that user's documents; the exchanged
    token's `act.sub` is the service client.
  - [x] Task 12.4. `LegacyImplicitEndToEndIT`: auth-server with `dev,legacy-implicit`; Playwright opens
    `/legacy-implicit/`, signs in, the page shows the token claims and `state` matched; same flow with `spa-public`
    gets `unsupported_response_type`.

### Group 5 – Docs, shared files and final gate (Parallelizable: no — touches shared files and runs the whole build)

- [x] Task 13. Documentation and repository notes _(untagged)_
  - [x] Task 13.1. _(CLAUDE.md: feature names, V800, service-client modules and profiles, legacy-implicit exception, design decisions and limits; apis/README.md: service-client generated client)_ CLAUDE.md: feature names `clientauth`, `exchange`, `par`; Flyway `V800`; service-client modules and
    profiles; the legacy-implicit exception, design decisions and limits (no CRL/OCSP for `tls_client_auth`, implicit is
    legacy and off by default); `apis/README.md` (service-client generated client).
  - [x] Task 13.2. _(docs: new client-credentials.adoc and legacy-implicit.adoc; updated clients, resource-server, reference, data-model, nav; Antora build clean, no unresolved includes)_ Run `/iru-update-docs` for the Antora pages (new `client-credentials.adoc`, `legacy-implicit.adoc`,
    updates to `clients.adoc`, `resource-server.adoc`, `reference.adoc`, nav).
- [x] Task 14. Final gate and PR notes _(untagged)_
  - [x] Task 14.1. _(owner audited the `ClientRegistration.java` findings as false positives; whole-repository scan: 0 new, 0 unlabelled, 56 entries all `is_secret: false`; no key, certificate or JWK file is committed)_ `detect-secrets` clean (`/iru-check-security`); no key, certificate or JWK file committed.
  - [x] Task 14.2. _(full `./mvnw -B clean verify` green: 46 modules, Checkstyle/PMD/CPD/SpotBugs 0, enforcer, ArchUnit, OpenApiDriftIT, e2e 24 ITs; JaCoCo aggregate 99.11% line / 97.60% branch; fixed a startup race in e2e `RunningAuthServer`, see PR notes)_ `./mvnw -B clean verify` through the `iru-gate-runner` agent (Checkstyle, PMD/CPD, SpotBugs,
    JaCoCo 80/70, enforcer, ArchUnit, `OpenApiDriftIT`); fix any finding at its source.
  - [x] Task 14.3. _(PR notes appended below)_ Append "PR notes" to this file: every `tag::` added (by file), the shared files touched and why, and
    the limits (implicit legacy-only, PKIX without revocation).

Run each task's tests through the `iru-gate-runner` agent, for example
`Agent({description: "Run tests for ClientAuthenticationIT", subagent_type: "iru-gate-runner", prompt: "Invoke Skill({skill: \"iru-java-test\", args: \"ClientAuthenticationIT\"}) and report a compact summary"})`,
never directly in the main conversation.

## PR notes

### Tags added (by file)

- `apis/auth-server/rest-server/auth-server-api-v1.yaml`: `clients-auth-settings`, `clients-auth-settings-response`
- `auth-server/api/web/.../clients/ClientJwksParser.java`: `clients-auth-settings`
- `auth-server/api/web/.../clientauth/`: `ClientAuthConfiguration` `clientauth-decoder-bean`; `ClientAuthProtocolChainCustomizer` `clientauth-chain`; `ClientCertificateVerifier` `clientauth-certificate-verifier`; `MtlsProperties` `clientauth-mtls-properties`; `RegisteredJwksClientAssertionDecoderFactory` `clientauth-assertion-decoder`; `ReplayRejectingJwtValidator` `clientauth-replay-validator`
- `auth-server/api/web/.../exchange/TokenExchangeAudienceContributor.java`: `exchange-claims`
- `auth-server/api/web/.../implicit/`: `LegacyImplicitAuthenticationProvider` `implicit-provider`; `LegacyImplicitAuthorizationRequestConverter` `implicit-converter`; `LegacyImplicitConfiguration` `implicit-chain-config`; `LegacyImplicitProperties` `implicit-properties`; `LegacyImplicitProtocolChainCustomizer` `implicit-chain`; `LegacyImplicitResponseHandler` `implicit-response-handler`
- `auth-server/api/web/.../par/ParConfiguration.java`: `par-chain`
- `auth-server/api/web/src/main/resources/legacy-implicit/index.html` and `legacy-implicit.js`: `implicit-demo-page`
- `auth-server/boot/src/main/resources/application.yml`: `client-assertion-config`, `mtls-config`, `par-config`; `application-legacy-implicit.yml`: `legacy-implicit-config`
- `auth-server/boot/src/test/.../ClientAdminIT.java`: `clients-auth-settings`
- `auth-server/infrastructure/persistence/.../RegisteredClientMapper.java`: `clients-auth-settings`; `V800__client_assertion_jtis.sql`: `client-assertion-schema`
- `resource-server/api/web/.../security/SecurityConfig.java`: `resource-server-bound-tokens` (nested in `resource-server-security`)
- `service-client/infrastructure/resourceserver/...`: `DPoPClientHttpRequestInterceptor` `dpop-client`; `DocumentCalls` `service-client-gateway`; `DocumentsApis` `service-client-documents-client`; `OAuth2ClientConfiguration` `client-credentials-manager`, `token-exchange-client`; `PrivateKeyJwkResolver` `private-key-jwt-client`

### Shared files touched and why

CLAUDE.md and `apis/README.md` (feature, Flyway, service-client and limits notes); the clients contract, `ClientRegistration` and every constructor call, `RegisteredClientMapper`, `CreateClientUseCase`, `RotateClientSecretUseCase`, `DefaultClientDefinitions` (new client settings, secret only for `client_secret_*`); `application.yml` and the new `application-legacy-implicit.yml` (settings); resource-server `SecurityConfig` (DPoP); the poms, `coverage/pom.xml` and `docs/antora.yml` (new service-client modules and scans); `e2e-tests` helpers; `.secrets.baseline` (line numbers and two new entries from the scanner, unlabelled); docs pages `client-credentials.adoc`, `legacy-implicit.adoc`, `clients.adoc`, `resource-server.adoc`, `reference.adoc`, `data-model.adoc`, `nav.adoc`.

### Limits

Implicit exists only as an opt-in legacy demo (`legacy-implicit` profile, one client, never for production); `tls_client_auth` validates the chain by PKIX without revocation (no CRL/OCSP); the token-exchange provider ignores `resource` and `audience` is honoured only within the client's own audiences; no client-side DPoP in Spring Security 7.1.2 (hand-wired with Nimbus); the resource server's DPoP replay cache is per instance and its `htu` check needs the unaltered request URL.

### Other notes

- Fixed an intermittent e2e failure: `RunningAuthServer.start` returned once the seeded credentials were logged, before `SigningKeyBootstrapRunner` stored the first signing key, so a token request with no prior sign-in got `500 Failed to select a JWK signing key`. It now waits for a row in `signing_keys` (test code only).
- Task 14.1 secret scan: the findings (`ClientRegistration.java` lines 75 and 84, the auth-method name constants, and the Private Key / Secret Keyword findings in service-client and e2e-tests sources) were audited by the owner as false positives; the whole-repository scan reports 0 new and 0 unlabelled findings (56 baseline entries, all `is_secret: false`).
