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

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import tools.jackson.databind.JsonNode;

/**
 * Checks the passkey sign-in as the login chain applies it: the endpoints the chain permits (with CSRF on), the
 * passkey as the second factor after a password and as the only factor, the merge of the factors of the session, the
 * resumption of the saved authorization request with a new session id, the claims of the tokens, the audit trail,
 * the refusal of a disabled account, the answer to a failed or unknown sign-in and the account API. The relying party
 * operations are mocked, so the tests need no authenticator: they exercise the filter, the provider, the
 * multi-factor framework and the token customizers, not the cryptography of the credential, which the WebAuthn4J
 * library and the end-to-end tests with a virtual authenticator cover.
 */
class PasskeyConfigurationIT extends AbstractPasskeyFlow {

    /** Name of the header that carries the bearer token. */
    private static final String AUTHORIZATION = "Authorization";

    /** Prefix of the value of a bearer token. */
    private static final String BEARER = "Bearer ";

    /** Path of the passkeys of the account API. */
    private static final String PASSKEYS_API = "/api/account/passkeys";

    /** Lifetime of the options of a ceremony. */
    private static final Duration OPTIONS_TIMEOUT = Duration.ofMinutes(5);

    /** {@code amr} of a user who presented a password and a passkey. */
    private static final List<String> PASSWORD_AND_PASSKEY_AMR = List.of("pwd", "hwk", "mfa");

    /** Relying party operations, which would verify the cryptography of the credential. */
    @MockitoBean
    private WebAuthnRelyingPartyOperations relyingParty;

    /**
     * Makes the mocked relying party answer options for every authentication ceremony.
     */
    @BeforeEach
    void stubTheOptions() {
        when(relyingParty.createCredentialRequestOptions(any())).thenReturn(PublicKeyCredentialRequestOptions
                .builder().challenge(Bytes.random()).rpId("localhost").timeout(OPTIONS_TIMEOUT).build());
    }

    /**
     * Verifies that the options endpoint is covered by the login chain: anonymous callers get options (so a user can
     * start a passkey sign-in) but only with the CSRF token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authenticationOptions_whenAnonymous_arePublicButKeepCsrfProtection() throws Exception {
        getMockMvc().perform(post(AUTHENTICATION_OPTIONS).contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());

        getMockMvc().perform(post(AUTHENTICATION_OPTIONS).with(csrf()).contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challenge").exists());
    }

    /**
     * Verifies the whole second-factor flow: a user with a passkey who signed in with the password is sent to the
     * second-factor page, which offers the passkey; presenting it keeps the password factor (so the tokens report
     * both and {@code mfa}), resumes the saved authorization request in the JSON the framework answers, changes the
     * session id, records the sign-in, and issues the same roles, tenant and audiences as a password sign-in. The
     * fresh multi-factor token then renames and deletes the passkey through the account API.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenPasskeyCompletesTheSecondFactor_mergesTheFactorsResumesTheRequestAndIssuesTheSameClaims()
            throws Exception {
        final var user = getFixtures().createUser();
        final var passkey = seedPasskey(user.username(), "Laptop");
        when(relyingParty.authenticate(any())).thenReturn(entityOf(user));
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(user, client, verifier, Map.of(), session);
        expectSecondFactorPage(authorizeUri, session);
        assertTrue(secondFactorPage(session).contains("data-passkey-button"), "The page must offer the passkey");
        final var sessionId = session.getId();
        final var successesBefore = countEvents("LOGIN_SUCCESS");

        authenticateWithPasskey(session)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.redirectUrl", containsString(client.clientId())));

        assertNotEquals(sessionId, session.getId(), "The session id must change when the passkey is presented");
        assertEquals(successesBefore + 1, countEvents("LOGIN_SUCCESS"), "The sign-in must reach the audit trail");
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);
        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        final var id = AuthServerFixtures.claimsOf(tokens.get("id_token").asString());
        assertEquals(PASSWORD_AND_PASSKEY_AMR, strings(access.get(AMR)));
        assertEquals(PASSWORD_AND_PASSKEY_AMR, strings(id.get(AMR)));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, access.get(ACR).asString());
        assertEquals(List.of("ROLE_USER"), strings(access.get(ROLES)));
        assertEquals(AuthServerFixtures.TENANT, access.get(TENANT).asString());
        assertSameClaimsAsAPasswordSignIn(access);

        final var bearer = BEARER + tokens.get("access_token").asString();
        getMockMvc().perform(get(PASSKEYS_API).header(AUTHORIZATION, bearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(passkey.credentialId()))
                .andExpect(jsonPath("$[0].label").value("Laptop"));
        getMockMvc().perform(patch(PASSKEYS_API + "/" + passkey.credentialId()).header(AUTHORIZATION, bearer)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"label\":\"Renamed\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.label").value("Renamed"));
        getMockMvc().perform(delete(PASSKEYS_API + "/" + passkey.credentialId()).header(AUTHORIZATION, bearer))
                .andExpect(status().isNoContent());
        assertEquals(0, countCredentials(passkey.credentialId()));
    }

    /**
     * Verifies the passkey as the only factor: it satisfies the policy on its own, the tokens report {@code hwk} and,
     * because only one factor was presented, the password {@code acr}, so the step-up of the account API (which
     * demands the multi-factor class) refuses it with the RFC 9470 challenge, and presenting the same passkey again
     * on the second-factor page does not change that: a user whose only second factor is a passkey cannot reach the
     * multi-factor class with it alone.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenPasskeyIsTheOnlyFactor_isStrongEnoughButNeverReachesTheMultiFactorClass() throws Exception {
        final var user = getFixtures().createUser();
        final var passkey = seedPasskey(user.username(), "Laptop");
        when(relyingParty.authenticate(any())).thenReturn(entityOf(user));
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var session = new MockHttpSession();
        final var authorizeUri = AuthServerFixtures.authorizeUri(client, verifier, Map.of());
        getMockMvc().perform(get(authorizeUri).session(session)).andExpect(status().is3xxRedirection());

        authenticateWithPasskey(session)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.redirectUrl", containsString(client.clientId())));

        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);
        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(List.of("hwk"), strings(access.get(AMR)));
        assertEquals(AuthenticationContextClass.PASSWORD, access.get(ACR).asString());
        assertEquals(List.of("ROLE_USER"), strings(access.get(ROLES)));
        assertEquals(AuthServerFixtures.TENANT, access.get(TENANT).asString());
        assertSameClaimsAsAPasswordSignIn(access);

        final var bearer = BEARER + tokens.get("access_token").asString();
        getMockMvc().perform(get(PASSKEYS_API).header(AUTHORIZATION, bearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(passkey.credentialId()));
        getMockMvc().perform(delete(PASSKEYS_API + "/" + passkey.credentialId()).header(AUTHORIZATION, bearer))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                        containsString("insufficient_user_authentication")));
        assertEquals(1, countCredentials(passkey.credentialId()));

        final var stepUpUri = AuthServerFixtures.authorizeUri(client, newVerifier(),
                Map.of("acr_values", AuthenticationContextClass.MULTI_FACTOR));
        expectSecondFactorPage(stepUpUri, session);
        authenticateWithPasskey(session).andExpect(status().isOk());
        expectSecondFactorPage(stepUpUri, session);
    }

    /**
     * Verifies that a disabled account is refused when it presents a passkey, like it is with the password, and
     * that the failure reaches the audit trail.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenAccountIsDisabled_isRefusedAndRecorded() throws Exception {
        final var user = getFixtures().createUser();
        seedPasskey(user.username(), "Laptop");
        getJdbc().sql("UPDATE users SET enabled = FALSE WHERE username = ?").param(user.username()).update();
        when(relyingParty.authenticate(any())).thenReturn(entityOf(user));
        final var failuresBefore = countEvents("LOGIN_FAILURE");

        authenticateWithPasskey(new MockHttpSession())
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(""));

        assertEquals(failuresBefore + 1, countEvents("LOGIN_FAILURE"), "The failure must reach the audit trail");
    }

    /**
     * Verifies that an assertion the relying party rejects and a passkey of an account that does not exist are
     * answered identically: {@code 401} without a body, so the sign-in does not reveal whether an account exists.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenAssertionIsRejectedOrAccountIsUnknown_answersTheSameFailure() throws Exception {
        when(relyingParty.authenticate(any())).thenThrow(new IllegalArgumentException("bad signature"));
        final var rejected = authenticateWithPasskey(new MockHttpSession()).andReturn().getResponse();

        doReturn(entityNamed("ghost-" + AuthServerFixtures.randomValue())).when(relyingParty).authenticate(any());
        final var unknown = authenticateWithPasskey(new MockHttpSession()).andReturn().getResponse();

        assertEquals(HttpStatus.UNAUTHORIZED.value(), rejected.getStatus());
        assertEquals(rejected.getStatus(), unknown.getStatus());
        assertEquals(rejected.getContentAsString(), unknown.getContentAsString());
        assertEquals("", unknown.getContentAsString());
        assertNotNull(rejected.getHeaderNames());
        assertEquals(rejected.getHeaderNames().stream().filter(name -> !"Set-Cookie".equals(name)).sorted().toList(),
                unknown.getHeaderNames().stream().filter(name -> !"Set-Cookie".equals(name)).sorted().toList());
    }

    /**
     * Verifies that a passkey sign-in post without the CSRF token is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenCsrfTokenIsMissing_isForbidden() throws Exception {
        getMockMvc().perform(post(AUTHENTICATION).contentType(MediaType.APPLICATION_JSON).content(ASSERTION))
                .andExpect(status().isForbidden());
    }

    /**
     * Fails unless the claims of a passkey sign-in carry the same roles, tenant and audiences as those of a password
     * sign-in of an equivalent user.
     *
     * @param passkeyClaims the claims of the access token of the passkey sign-in.
     * @throws Exception if a request cannot be performed.
     */
    private void assertSameClaimsAsAPasswordSignIn(final JsonNode passkeyClaims)
            throws Exception {
        final var other = getFixtures().createUser();
        final var tokens = getFixtures().authorizationCodeTokens(other, getFixtures().createCodeClient());
        final var password = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(strings(password.get(ROLES)), strings(passkeyClaims.get(ROLES)));
        assertEquals(password.get(TENANT).asString(), passkeyClaims.get(TENANT).asString());
        assertEquals(strings(password.get(AUD)), strings(passkeyClaims.get(AUD)));
    }

    /**
     * Builds the user entity a passkey of a user belongs to.
     *
     * @param user the user.
     * @return the user entity, named like the account.
     */
    private static PublicKeyCredentialUserEntity entityOf(final AuthServerFixtures.TestUser user) {
        return entityNamed(user.username());
    }

    /**
     * Builds a user entity.
     *
     * @param name name of the entity.
     * @return the user entity.
     */
    private static PublicKeyCredentialUserEntity entityNamed(final String name) {
        return ImmutablePublicKeyCredentialUserEntity.builder().name(name).id(Bytes.random()).displayName(name)
                .build();
    }
}
