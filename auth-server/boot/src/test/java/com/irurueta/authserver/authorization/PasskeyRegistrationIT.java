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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.JsonNode;

/**
 * Checks the registration side of the passkeys against the real WebAuthn operations and the real repositories: that
 * the user entity the framework creates carries the username (the account lookups and the merge of factors depend on
 * it), that a session which only presented the password of an account that still has to complete its second factor
 * cannot enrol a passkey, that the framework's own removal and registration page are gone, and that the options of an
 * authentication never depend on a username.
 */
class PasskeyRegistrationIT extends AbstractPasskeyFlow {

    /** A registration post, as the page script sends it (it never gets verified: the session is refused first). */
    private static final String REGISTRATION_BODY = "{\"publicKey\":{\"credential\":{},\"label\":\"Attacker\"}}";

    /** Port the passkeys are read through. */
    @Autowired
    private PasskeyRepository passkeys;

    /**
     * Verifies that a session that only presented the password of an account that has an authenticator app is sent to
     * the second-factor page by every registration endpoint and by the account page, and that nothing is created:
     * it could otherwise enrol a passkey it controls and sign in with it, skipping the second factor. Once the second
     * factor is presented the same session may register.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void registration_whenSessionHasOnlyThePasswordAndTheAccountNeedsASecondFactor_isRefusedUntilItIsPresented()
            throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var session = signInWithThePasswordOnly(enrolled.user());

        expectSecondFactor(postJson(REGISTRATION_OPTIONS, session));
        expectSecondFactor(getMockMvc().perform(post(REGISTRATION).session(session).with(csrf())
                .with(AbstractMfaFlow::sendsTheSessionCookie).contentType(MediaType.APPLICATION_JSON)
                .content(REGISTRATION_BODY)));
        expectSecondFactor(getMockMvc().perform(get(ACCOUNT_PAGE).session(session)));
        assertEquals(0, countUserEntities(enrolled.user().username()), "Nothing may be created for the session");

        assertAccepted(postSecondFactor(session, getTools().codeNow(enrolled.id(), 0), false, false));
        postJson(REGISTRATION_OPTIONS, session).andExpect(status().isOk());
        assertEquals(1, countUserEntities(enrolled.user().username()));
    }

    /**
     * Verifies that the user entity created when the registration starts is named like the account (so the factor
     * merge and the lookup of the passkeys of a username find it), has the id the options carry, and that the
     * credentials the account already has are sent as {@code excludeCredentials}.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void registrationOptions_whenSessionSatisfiesThePolicy_createTheUserEntityNamedLikeTheUsername()
            throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var username = enrolled.user().username();
        final var session = signInCompletingTheSecondFactor(enrolled);

        final var first = optionsOf(postJson(REGISTRATION_OPTIONS, session).andExpect(status().isOk()));

        final var handle = getJdbc().sql("SELECT id FROM user_entities WHERE name = ?").param(username)
                .query(String.class).single();
        assertEquals(username, first.get("user").get("name").asString());
        assertEquals(handle, first.get("user").get("id").asString());
        assertEquals("localhost", first.get("rp").get("id").asString());
        assertEquals(0, first.get("excludeCredentials").size());
        assertEquals(handle, passkeys.findUserIdByUsername(username).orElseThrow());

        final var seeded = seedPasskey(username, "Laptop");
        final var second = optionsOf(postJson(REGISTRATION_OPTIONS, session).andExpect(status().isOk()));
        assertEquals(handle, seeded.userHandle());
        assertEquals(List.of(seeded.credentialId()),
                second.get("excludeCredentials").valueStream().map(entry -> entry.get("id").asString()).toList());
    }

    /**
     * Verifies that an anonymous request to a registration endpoint is sent to sign in and creates nothing.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void registration_whenNobodyIsSignedIn_isSentToTheLoginPage() throws Exception {
        final var before = countAllUserEntities();

        postJson(REGISTRATION_OPTIONS, new MockHttpSession()).andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));

        assertEquals(before, countAllUserEntities());
    }

    /**
     * Verifies that the framework's removal of a credential is denied, even to a session that satisfies the policy
     * (the only removal is the account API, which asks for a recent multi-factor sign-in), and that the framework's
     * default registration page does not exist.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void removal_whenFrameworkEndpointIsCalled_isDeniedAndTheDefaultPageIsGone() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var passkey = seedPasskey(enrolled.user().username(), "Laptop");
        final var session = signInCompletingTheSecondFactor(enrolled);

        getMockMvc().perform(delete(REGISTRATION + "/" + passkey.credentialId()).session(session).with(csrf())
                        .with(AbstractMfaFlow::sendsTheSessionCookie))
                .andExpect(status().isForbidden());
        getMockMvc().perform(get(REGISTRATION).session(session)).andExpect(status().isNotFound());

        assertEquals(1, countCredentials(passkey.credentialId()), "The credential must not be removed");
    }

    /**
     * Verifies that the framework's removal is refused too to a session that has not completed its second factor,
     * and still removes nothing.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void removal_whenSessionHasOnlyThePassword_removesNothing() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var passkey = seedPasskey(enrolled.user().username(), "Laptop");
        final var session = signInWithThePasswordOnly(enrolled.user());

        expectSecondFactor(getMockMvc().perform(delete(REGISTRATION + "/" + passkey.credentialId()).session(session)
                .with(csrf()).with(AbstractMfaFlow::sendsTheSessionCookie)));

        assertEquals(1, countCredentials(passkey.credentialId()));
    }

    /**
     * Verifies that the options of an authentication never depend on a username: an anonymous caller gets none of
     * the credentials of any account, and a signed-in session only those of its own account, so the endpoint does
     * not tell whether an account exists or what it has.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authenticationOptions_whenAnonymousOrSignedIn_onlyNameTheCredentialsOfTheSession() throws Exception {
        final var first = getFixtures().createEnrolledUser(getTools());
        final var second = getFixtures().createUser();
        final var own = seedPasskey(first.user().username(), "Own");
        seedPasskey(second.username(), "Someone else's");

        final var anonymous = optionsOf(postJson(AUTHENTICATION_OPTIONS, new MockHttpSession())
                .andExpect(status().isOk()));
        assertEquals(0, anonymous.path("allowCredentials").size());

        final var signedIn = optionsOf(postJson(AUTHENTICATION_OPTIONS, signInCompletingTheSecondFactor(first))
                .andExpect(status().isOk()));
        assertEquals(List.of(own.credentialId()),
                signedIn.get("allowCredentials").valueStream().map(entry -> entry.get("id").asString()).toList());
    }

    /**
     * Fails unless the answer redirects to the second-factor page.
     *
     * @param answer the answer of a request.
     * @throws Exception if the answer cannot be read.
     */
    private static void expectSecondFactor(final ResultActions answer) throws Exception {
        answer.andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/login/second-factor"));
    }

    /**
     * Reads the options a ceremony answered.
     *
     * @param answer the answer of the options endpoint.
     * @return the options as a JSON tree.
     * @throws Exception if the answer cannot be read.
     */
    private static JsonNode optionsOf(final ResultActions answer) throws Exception {
        return AuthServerFixtures.parse(answer.andReturn().getResponse().getContentAsString());
    }

    /**
     * Counts the user entities of a username.
     *
     * @param username name of the user entity.
     * @return the number of entities.
     */
    private long countUserEntities(final String username) {
        return getJdbc().sql("SELECT count(*) FROM user_entities WHERE name = ?").param(username)
                .query(Long.class).single();
    }

    /**
     * Counts every user entity.
     *
     * @return the number of entities.
     */
    private long countAllUserEntities() {
        return getJdbc().sql("SELECT count(*) FROM user_entities").query(Long.class).single();
    }
}
