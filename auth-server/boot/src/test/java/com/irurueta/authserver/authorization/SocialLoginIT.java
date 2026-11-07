/*
 * Copyright (C) 2026 Alberto Irurueta Carro (alberto@irurueta.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.irurueta.authserver.authorization;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Checks the sign-in with external providers end to end, as the whole application wires it, against fake providers
 * that answer over HTTP (Google as the OpenID Connect provider that does not vouch for multi-factor authentication,
 * GitHub as the plain OAuth 2.0 one and Apple with the client secret the application signs): the first sign-in
 * provisions an account, a verified e-mail address links an existing account and an unverified one never does, the
 * tokens carry the local {@code sub}, the {@code idp} and the {@code amr} of the sign-in, a provider that is not
 * trusted for multi-factor authentication still leads to the second-factor step, and linked identities are removed
 * through the account API under step-up. Every client id, secret, signing key and Apple key is generated at run time.
 */
class SocialLoginIT extends AbstractSocialFlow {

    /** Client id of Google, generated for the run. */
    private static final String GOOGLE_CLIENT_ID = "google-" + UUID.randomUUID();

    /** Client id of Apple, generated for the run. */
    private static final String APPLE_CLIENT_ID = "apple-" + UUID.randomUUID();

    /** Client id of GitHub, generated for the run. */
    private static final String GITHUB_CLIENT_ID = "github-" + UUID.randomUUID();

    /** Team id of Apple. */
    private static final String TEAM_ID = "TEAM123456";

    /** Key id of the Apple key. */
    private static final String KEY_ID = "KEY1234567";

    /** Issuer of the ID tokens of Google. */
    private static final String GOOGLE_ISSUER = "https://accounts.google.com";

    /** Issuer of the ID tokens of Apple. */
    private static final String APPLE_ISSUER = "https://appleid.apple.com";

    /** Audience of the client secret of Apple. */
    private static final String APPLE_AUDIENCE = "https://appleid.apple.com";

    /** Path of the linked identities of the account API. */
    private static final String IDENTITIES = "/api/account/identities";

    /** Name of the header with the credential of an API request. */
    private static final String AUTHORIZATION_HEADER = "Authorization";

    /** The challenge of an operation that needs a recent multi-factor sign-in. */
    private static final String STEP_UP_CHALLENGE = "Bearer error=\"insufficient_user_authentication\", "
            + "acr_values=\"urn:irurueta:acr:mfa\", max_age=\"300\"";

    /** The longest the Apple client secret may live, as the application's default says. */
    private static final Duration MAX_SECRET_LIFETIME = Duration.ofMinutes(5);

    /** The key of Apple, generated for the run. */
    private static final KeyPair APPLE_KEY = generateAppleKey();

    /**
     * Configures four providers with values generated for the run; Microsoft is left out.
     *
     * @param registry registry of the properties of the context.
     */
    @DynamicPropertySource
    static void providers(final DynamicPropertyRegistry registry) {
        registry.add("authserver.social.providers.google.client-id", () -> GOOGLE_CLIENT_ID);
        registry.add("authserver.social.providers.google.client-secret", () -> UUID.randomUUID().toString());
        registry.add("authserver.social.providers.github.client-id", () -> GITHUB_CLIENT_ID);
        registry.add("authserver.social.providers.github.client-secret", () -> UUID.randomUUID().toString());
        registry.add("authserver.social.providers.apple.client-id", () -> APPLE_CLIENT_ID);
        registry.add("authserver.social.providers.apple.team-id", () -> TEAM_ID);
        registry.add("authserver.social.providers.apple.key-id", () -> KEY_ID);
        registry.add("authserver.social.providers.apple.private-key",
                () -> Base64.getEncoder().encodeToString(APPLE_KEY.getPrivate().getEncoded()));
    }

    /**
     * Verifies that the first sign-in of a person the server does not know provisions an account named after the
     * verified address and links the provider's identity to it, and that the browser ends up signed in as it.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheFirstLoginHasAVerifiedEmail_provisionsAndLinksAnAccount() throws Exception {
        final var email = "new-" + UUID.randomUUID() + "@example.com";
        final var subject = "google-subject-" + UUID.randomUUID();
        final var session = new MockHttpSession();

        final var result = signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims(subject, email, true));

        assertFalse(result.getResponse().getRedirectedUrl().endsWith(FAILED));
        final var account = accountOf(email).orElseThrow();
        assertEquals(email, account.username());
        assertTrue(account.enabled());
        assertEquals(email, signedInName(session).orElseThrow());
        final var linked = identitiesOf(account);
        assertEquals(1, linked.size());
        assertEquals(IdentityProvider.GOOGLE, linked.getFirst().provider());
        assertEquals(subject, linked.getFirst().subject());
    }

    /**
     * Verifies that a verified address that belongs to an existing account links the identity to that account, and
     * provisions nothing.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheVerifiedEmailBelongsToAnAccount_linksTheIdentityToIt() throws Exception {
        final var user = getFixtures().createUser();
        final var session = new MockHttpSession();

        signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims("subject-" + UUID.randomUUID(), user.email(), true));

        assertEquals(user.username(), signedInName(session).orElseThrow());
        final var account = accountOf(user.email()).orElseThrow();
        assertEquals(user.username(), account.username());
        assertEquals(1, identitiesOf(account).size());
    }

    /**
     * Verifies that an address the provider did not verify never links an identity to the account that owns it: the
     * sign-in is refused and nobody is signed in.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheEmailIsNotVerified_isRefusedAndLinksNothing() throws Exception {
        final var user = getFixtures().createUser();
        final var session = new MockHttpSession();

        final var result = signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims("subject-" + UUID.randomUUID(), user.email(), false));

        assertRefused(result, session);
        assertTrue(identitiesOf(accountOf(user.email()).orElseThrow()).isEmpty());
    }

    /**
     * Verifies that an unverified address of a person the server does not know provisions no account.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheFirstLoginHasAnUnverifiedEmail_provisionsNothing() throws Exception {
        final var email = "unverified-" + UUID.randomUUID() + "@example.com";
        final var session = new MockHttpSession();

        final var result = signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims("subject-" + UUID.randomUUID(), email, false));

        assertRefused(result, session);
        assertTrue(accountOf(email).isEmpty());
    }

    /**
     * Verifies that a returning identity signs in to the account it is linked to, without a second link or account,
     * even when the provider reports another address.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheIdentityIsAlreadyLinked_signsInToTheSameAccount() throws Exception {
        final var email = "again-" + UUID.randomUUID() + "@example.com";
        final var subject = "subject-" + UUID.randomUUID();
        signInWithOidc(new MockHttpSession(), "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims(subject, email, true));
        final var session = new MockHttpSession();

        signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims(subject, "other-" + UUID.randomUUID() + "@example.com", true));

        assertEquals(email, signedInName(session).orElseThrow());
        assertEquals(1, identitiesOf(accountOf(email).orElseThrow()).size());
    }

    /**
     * Verifies that a disabled account cannot be entered through a linked identity.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheLinkedAccountIsDisabled_isRefused() throws Exception {
        final var email = "disabled-" + UUID.randomUUID() + "@example.com";
        final var subject = "subject-" + UUID.randomUUID();
        signInWithOidc(new MockHttpSession(), "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims(subject, email, true));
        final var account = accountOf(email).orElseThrow();
        disable(account);
        final var session = new MockHttpSession();

        final var result = signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims(subject, email, true));

        assertRefused(result, session);
    }

    /**
     * Verifies the claims of the tokens a federated sign-in leads to: the {@code sub} is the local account, the
     * {@code idp} names the provider and the {@code amr} lists the federated sign-in alone.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void tokens_whenSignedInWithAProvider_carryTheLocalSubIdpAndFederatedAmr() throws Exception {
        final var email = "claims-" + UUID.randomUUID() + "@example.com";
        final var session = new MockHttpSession();
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var authorizeUri = beginAuthorization(client, verifier, session);

        signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims("provider-subject-" + UUID.randomUUID(), email, true));
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(email, access.get(SUB).asString());
        assertEquals("google", access.get("idp").asString());
        assertEquals(List.of("fed"), strings(access.get(AMR)));
        assertEquals(AuthenticationContextClass.PASSWORD, access.get(ACR).asString());
        final var id = AuthServerFixtures.claimsOf(tokens.get("id_token").asString());
        assertEquals(email, id.get(SUB).asString());
        assertEquals("google", id.get("idp").asString());
    }

    /**
     * Verifies that the verified primary address GitHub lists provisions an account named after it, and that the
     * identity is linked under GitHub's numeric id.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenGitHubListsAVerifiedPrimaryEmail_provisionsAndLinksAnAccount() throws Exception {
        final var email = "octo-" + UUID.randomUUID() + "@example.com";
        final var id = Math.abs(UUID.randomUUID().getMostSignificantBits());
        final var session = new MockHttpSession();
        FakeIdentityProviders.stubGitHub("gho-" + UUID.randomUUID(), id, List.of(
                Map.of("email", "secondary@example.com", "primary", false, "verified", true),
                Map.of("email", email, "primary", true, "verified", true)));

        final var state = authorizationRequest(session, "github").getFirst("state");
        callback(session, "github", state);

        assertEquals(email, signedInName(session).orElseThrow());
        final var linked = identitiesOf(accountOf(email).orElseThrow());
        assertEquals(IdentityProvider.GITHUB, linked.getFirst().provider());
        assertEquals(Long.toString(id), linked.getFirst().subject());
    }

    /**
     * Verifies that GitHub's primary address, when it is not verified, provisions nothing: the sign-in is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenGitHubsPrimaryEmailIsNotVerified_isRefused() throws Exception {
        final var email = "unverified-octo-" + UUID.randomUUID() + "@example.com";
        final var session = new MockHttpSession();
        final var id = Math.abs(UUID.randomUUID().getMostSignificantBits());
        FakeIdentityProviders.stubGitHub("gho-" + UUID.randomUUID(), id,
                List.of(Map.of("email", email, "primary", true, "verified", false)));

        final var state = authorizationRequest(session, "github").getFirst("state");
        final var result = callback(session, "github", state);

        assertRefused(result, session);
        assertTrue(accountOf(email).isEmpty());
    }

    /**
     * Verifies the shape of the client secret the application sends Apple: an ES256 token signed by the registered
     * key, issued by the team for the client, for Apple's audience and short lived; and that the sign-in with the
     * posted answer of Apple provisions an account.
     *
     * @throws Exception if a request cannot be performed or the secret cannot be read.
     */
    @Test
    void signIn_whenApple_sendsAShortLivedEs256ClientSecretSignedWithTheTeamKey() throws Exception {
        final var email = "apple-" + UUID.randomUUID() + "@example.com";
        final var session = new MockHttpSession();
        final var claims = FakeIdentityProviders.userClaims("apple-subject-" + UUID.randomUUID(), email, true);
        claims.put("email_verified", "true");

        signInWithOidc(session, "apple", APPLE_ISSUER, APPLE_CLIENT_ID, claims);

        assertEquals(email, signedInName(session).orElseThrow());
        final var requests = FakeIdentityProviders.tokenRequests("apple");
        assertEquals(1, requests.size());
        assertEquals(APPLE_CLIENT_ID, requests.getFirst().get("client_id"));
        final var secret = SignedJWT.parse(requests.getFirst().get("client_secret"));
        assertEquals(JWSAlgorithm.ES256, secret.getHeader().getAlgorithm());
        assertEquals(KEY_ID, secret.getHeader().getKeyID());
        assertEquals(TEAM_ID, secret.getJWTClaimsSet().getIssuer());
        assertEquals(APPLE_CLIENT_ID, secret.getJWTClaimsSet().getSubject());
        assertEquals(List.of(APPLE_AUDIENCE), secret.getJWTClaimsSet().getAudience());
        final var lifetime = Duration.between(secret.getJWTClaimsSet().getIssueTime().toInstant(),
                secret.getJWTClaimsSet().getExpirationTime().toInstant());
        assertTrue(lifetime.compareTo(MAX_SECRET_LIFETIME) <= 0 && !lifetime.isNegative());
        assertTrue(secret.verify(new ECDSAVerifier((ECPublicKey) APPLE_KEY.getPublic())));
    }

    /**
     * Verifies that a provider that is not trusted for multi-factor authentication still leads to the second-factor
     * step, whatever its ID token claims: a user with an authenticator app is asked for a code, and the tokens then
     * show both factors.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenTheProviderIsNotTrustedForMfa_asksForTheSecondFactor() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var session = new MockHttpSession();
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var authorizeUri = beginAuthorization(client, verifier, session);
        final var claims = FakeIdentityProviders.userClaims(
                "subject-" + UUID.randomUUID(), enrolled.user().email(), true);
        claims.put("amr", List.of("pwd", "mfa"));

        signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID, claims);
        expectSecondFactorPage(authorizeUri, session);
        assertAccepted(postSecondFactor(session, getTools().codeNow(enrolled.id(), 0), false, false));
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(List.of("fed", "otp", "mfa"), strings(access.get(AMR)));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, access.get(ACR).asString());
        assertEquals("google", access.get("idp").asString());
    }

    /**
     * Verifies that an identity is unlinked through the account API only under step-up: a token without a recent
     * multi-factor sign-in is answered with the challenge and nothing is removed, and the token of the
     * multi-factor sign-in removes it.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void unlink_whenTheAccountHasASecondFactor_needsAStepUpToken() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var session = new MockHttpSession();
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var authorizeUri = beginAuthorization(client, verifier, session);
        signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims("subject-" + UUID.randomUUID(), enrolled.user().email(), true));
        expectSecondFactorPage(authorizeUri, session);
        assertAccepted(postSecondFactor(session, getTools().codeNow(enrolled.id(), 0), false, false));
        final var bearer = "Bearer " + completeAuthorization(authorizeUri, client, verifier, session)
                .get("access_token").asString();
        final var listed = getMockMvc().perform(get(IDENTITIES).header(AUTHORIZATION_HEADER, bearer))
                .andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].provider").value("google")).andReturn().getResponse().getContentAsString();
        final var identityId = AuthServerFixtures.parse(listed).get(0).get("id").asString();

        getMockMvc().perform(delete(IDENTITIES + "/" + identityId)
                        .with(jwt().jwt(token -> token.subject(enrolled.user().username()))))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", STEP_UP_CHALLENGE));
        assertEquals(1, identitiesOf(accountOf(enrolled.user().email()).orElseThrow()).size());
        getMockMvc().perform(delete(IDENTITIES + "/" + identityId).header(AUTHORIZATION_HEADER, bearer))
                .andExpect(status().isNoContent());

        assertTrue(identitiesOf(accountOf(enrolled.user().email()).orElseThrow()).isEmpty());
    }

    /**
     * Verifies that the only way to sign in to a provisioned account, its identity, is never removed, and that an
     * identity that does not exist is answered as not found.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void unlink_whenItIsTheLastWayToSignIn_isRefused() throws Exception {
        final var email = "last-" + UUID.randomUUID() + "@example.com";
        final var session = new MockHttpSession();
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var authorizeUri = beginAuthorization(client, verifier, session);
        signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims("subject-" + UUID.randomUUID(), email, true));
        final var bearer = "Bearer " + completeAuthorization(authorizeUri, client, verifier, session)
                .get("access_token").asString();
        final var identity = identitiesOf(accountOf(email).orElseThrow()).getFirst();

        getMockMvc().perform(delete(IDENTITIES + "/" + identity.id()).header(AUTHORIZATION_HEADER, bearer))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:problem:identity:last-sign-in-method"));
        getMockMvc().perform(delete(IDENTITIES + "/" + UUID.randomUUID()).header(AUTHORIZATION_HEADER, bearer))
                .andExpect(status().isNotFound());

        assertEquals(1, identitiesOf(accountOf(email).orElseThrow()).size());
    }

    /**
     * Generates the key of Apple.
     *
     * @return the key pair.
     */
    private static KeyPair generateAppleKey() {
        try {
            final var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("The Apple test key cannot be generated", e);
        }
    }
}
