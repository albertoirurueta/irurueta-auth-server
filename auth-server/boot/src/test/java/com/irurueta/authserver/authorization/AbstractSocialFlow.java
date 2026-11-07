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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityRepository;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * Base of the social login integration tests: it drives the browser side of a sign-in with an external provider
 * against {@link FakeIdentityProviders}. The real application does everything else (the authorization request, the
 * code exchange over HTTP, the ID token validation, the user information request, the account resolution and the
 * tokens), so a test only decides what the provider answers.
 */
@Import(FakeIdentityProvidersConfiguration.class)
abstract class AbstractSocialFlow extends AbstractMfaFlow {

    /** Path that starts a sign-in with a provider. */
    static final String AUTHORIZATION = "/oauth2/authorization/";

    /** Path that receives the answer of a provider. */
    static final String CALLBACK = "/login/oauth2/code/";

    /** Registration id of Apple, whose answer is posted instead of redirected. */
    static final String APPLE = "apple";

    /** Location a failed sign-in is sent to. */
    static final String FAILED = "/login?error";

    /** Name of the claim with the subject. */
    static final String SUB = "sub";

    /** Port that stores the users. */
    @Autowired
    private UserAccountRepository accounts;

    /** Port that stores the linked identities. */
    @Autowired
    private FederatedIdentityRepository identities;

    /**
     * Forgets what the previous test taught the fake providers.
     */
    @BeforeEach
    void resetProviders() {
        FakeIdentityProviders.reset();
    }

    /**
     * Signs in with an OpenID Connect provider: starts the sign-in, lets the provider answer with the given claims
     * (both in the ID token and in the user information) and delivers the answer to the application.
     *
     * @param session  browser session.
     * @param provider registration id of the provider.
     * @param issuer   issuer of the ID token.
     * @param clientId client id the application has at the provider.
     * @param claims   claims of the user (including {@code sub}); the ID token carries them all.
     * @return the answer of the callback.
     * @throws Exception if a request cannot be performed.
     */
    protected MvcResult signInWithOidc(final MockHttpSession session, final String provider, final String issuer,
            final String clientId, final Map<String, Object> claims) throws Exception {
        final var request = authorizationRequest(session, provider);
        final var nonce = request.getFirst("nonce");
        final var state = request.getFirst("state");
        assertNotNull(nonce);
        assertNotNull(state);
        FakeIdentityProviders.stubOidc(provider, FakeIdentityProviders.idToken(issuer, clientId, nonce, claims),
                claims);
        return callback(session, provider, state);
    }

    /**
     * Starts a sign-in and reads the parameters of the authorization request the application sends the browser to.
     *
     * @param session  browser session.
     * @param provider registration id of the provider.
     * @return the query parameters of the redirect.
     * @throws Exception if the request cannot be performed.
     */
    protected MultiValueMap<String, String> authorizationRequest(final MockHttpSession session, final String provider)
            throws Exception {
        final var location = getMockMvc().perform(get(AUTHORIZATION + provider).session(session))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertNotNull(location);
        final var decoded = new LinkedMultiValueMap<String, String>();
        UriComponentsBuilder.fromUriString(location).build().getQueryParams().forEach((name, values) -> values
                .forEach(value -> decoded.add(name, UriUtils.decode(value, StandardCharsets.UTF_8))));
        return decoded;
    }

    /**
     * Delivers the answer of a provider to the application, the way the provider's page does.
     *
     * @param session  browser session.
     * @param provider registration id of the provider.
     * @param state    the state of the authorization request.
     * @return the answer of the callback.
     * @throws Exception if the request cannot be performed.
     */
    protected MvcResult callback(final MockHttpSession session, final String provider, final String state)
            throws Exception {
        final var request = APPLE.equals(provider)
                ? post(CALLBACK + provider).session(session).param("code", "code").param("state", state)
                : get(CALLBACK + provider).session(session).param("code", "code").param("state", state);
        return getMockMvc().perform(request).andReturn();
    }

    /**
     * Checks that a callback was a refused sign-in: back to the login page with an error, and nobody signed in.
     *
     * @param result  the answer of the callback.
     * @param session the browser session.
     */
    protected static void assertRefused(final MvcResult result, final MockHttpSession session) {
        final var redirect = result.getResponse().getRedirectedUrl();
        assertNotNull(redirect);
        assertTrue(redirect.endsWith(FAILED), "Expected a failed sign-in but got " + redirect);
        assertEquals(Optional.empty(), signedInName(session));
    }

    /**
     * Reads the name of the user a session is signed in as.
     *
     * @param session the browser session.
     * @return the user name, empty when nobody is signed in.
     */
    protected static Optional<String> signedInName(final MockHttpSession session) {
        final var context = (SecurityContext) session.getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        return Optional.ofNullable(context).map(SecurityContext::getAuthentication)
                .filter(authentication -> authentication.isAuthenticated()
                        && !"anonymousUser".equals(authentication.getName()))
                .map(authentication -> authentication.getName());
    }

    /**
     * Makes an authorization request that the application answers by asking the user to sign in, so the request is
     * saved and resumed after the sign-in.
     *
     * @param client   client that asks for the code.
     * @param verifier PKCE code verifier.
     * @param session  browser session.
     * @return the URI of the authorization request.
     * @throws Exception if a request cannot be performed.
     */
    protected String beginAuthorization(final AuthServerFixtures.TestClient client, final String verifier,
            final MockHttpSession session) throws Exception {
        final var authorizeUri = AuthServerFixtures.authorizeUri(client, verifier, Map.of());
        getMockMvc().perform(get(authorizeUri).session(session)).andExpect(status().is3xxRedirection());
        return authorizeUri;
    }

    /**
     * Finds the account of an e-mail address.
     *
     * @param email the address.
     * @return the account, empty when there is none.
     */
    protected Optional<UserAccount> accountOf(final String email) {
        return accounts.findByEmail(email);
    }

    /**
     * Disables an account.
     *
     * @param account the account.
     */
    protected void disable(final UserAccount account) {
        accounts.save(new UserAccount(account.id(), account.username(), account.encodedPassword(), false,
                account.authorities(), account.email(), account.emailVerified(), account.tenant()));
    }

    /**
     * Lists the identities linked to an account.
     *
     * @param account the account.
     * @return the linked identities.
     */
    protected List<FederatedIdentity> identitiesOf(final UserAccount account) {
        return identities.findByUser(account.id());
    }

    /**
     * Builds the claims of an Entra ID user.
     *
     * @param subject  the subject.
     * @param email    the e-mail address.
     * @param tenantId the tenant of the token.
     * @param extra    other claims.
     * @return the claims.
     */
    protected static Map<String, Object> entraClaims(final String subject, final String email, final String tenantId,
            final Map<String, Object> extra) {
        final var claims = new LinkedHashMap<String, Object>();
        claims.put(SUB, subject);
        claims.put("email", email);
        claims.put("tid", tenantId);
        claims.putAll(extra);
        return claims;
    }
}
