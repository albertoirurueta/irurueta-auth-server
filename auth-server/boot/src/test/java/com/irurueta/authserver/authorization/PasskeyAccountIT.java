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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.application.mfa.CreateTrustedDeviceUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Checks the passkeys endpoints of the account API against the real application and the real tables: the list, the
 * rename and the deletion of the caller's passkeys, the step-up challenge that guards the deletion of an account with
 * a confirmed second factor, and that an account never sees or touches the passkeys of another one. The requests
 * carry a {@code jwt()} for the owner of the account, so the tests do not depend on the token endpoint. Every test
 * creates its own users.
 */
class PasskeyAccountIT extends AbstractPasskeyFlow {

    /** Path of the passkeys endpoint. */
    private static final String PASSKEYS_API = "/api/account/passkeys";

    /** Body of a rename request that is blank. */
    private static final String BLANK_LABEL = "{\"label\":\"   \"}";

    /** Body of a rename request. */
    private static final String RENAMED_LABEL = "{\"label\":\"Renamed\"}";

    /** Type of the problem answered for a passkey the account does not have. */
    private static final String NOT_FOUND_TYPE = "urn:problem:passkeys:passkey-not-found";

    /** Type of the problem answered for a label that is refused. */
    private static final String INVALID_LABEL_TYPE = "urn:problem:passkeys:invalid-label";

    /** Length of a label one character over the contract's maximum. */
    private static final int LABEL_TOO_LONG = 101;

    /** Seconds since a multi-factor sign-in that is too old for a step-up (the default maximum is five minutes). */
    private static final long OLD_SIGN_IN_SECONDS = 600;

    /** Summary of the browser of the trusted devices the tests create. */
    private static final String BROWSER = "Firefox on Linux";

    /** Creates the trusted devices of the tests. */
    @Autowired
    private CreateTrustedDeviceUseCase createTrustedDeviceUseCase;

    /** Port the trusted devices are read through. */
    @Autowired
    private TrustedDeviceRepository trustedDevices;

    /** Port that resolves the identifier of an account. */
    @Autowired
    private UserAccountRepository userAccounts;

    /**
     * Verifies that the endpoints need a bearer token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void passkeys_whenThereIsNoToken_returnUnauthorized() throws Exception {
        getMockMvc().perform(get(PASSKEYS_API)).andExpect(status().isUnauthorized());
        getMockMvc().perform(patch(PASSKEYS_API + "/AQID").contentType(MediaType.APPLICATION_JSON)
                .content(RENAMED_LABEL)).andExpect(status().isUnauthorized());
        getMockMvc().perform(delete(PASSKEYS_API + "/AQID")).andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that the list holds the passkeys of the caller, without any secret, and is empty for an account
     * without passkeys.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void listPasskeys_whenAccountHasPasskeys_listsThemAndNothingElse() throws Exception {
        final var user = getFixtures().createUser();
        final var empty = getFixtures().createUser();
        final var first = seedPasskey(user.username(), "Laptop");
        final var second = seedPasskey(user.username(), "Phone");

        getMockMvc().perform(get(PASSKEYS_API).with(bearerOf(user.username())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[?(@.id == '" + first.credentialId() + "')].label").value("Laptop"))
                .andExpect(jsonPath("$[?(@.id == '" + second.credentialId() + "')].label").value("Phone"))
                .andExpect(jsonPath("$[0].publicKey").doesNotExist());
        getMockMvc().perform(get(PASSKEYS_API).with(bearerOf(empty.username())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }

    /**
     * Verifies that a passkey is renamed (the label is trimmed) and that a blank label is rejected without changing
     * it.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void renamePasskey_whenLabelIsValid_renamesItAndRefusesABlankOne() throws Exception {
        final var user = getFixtures().createUser();
        final var passkey = seedPasskey(user.username(), "Laptop");
        final var path = PASSKEYS_API + "/" + passkey.credentialId();

        getMockMvc().perform(patch(path).with(bearerOf(user.username())).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"  Renamed  \"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(passkey.credentialId()))
                .andExpect(jsonPath("$.label").value("Renamed"));
        getMockMvc().perform(patch(path).with(bearerOf(user.username())).contentType(MediaType.APPLICATION_JSON)
                        .content(BLANK_LABEL))
                .andExpect(status().isBadRequest());

        getMockMvc().perform(get(PASSKEYS_API).with(bearerOf(user.username())))
                .andExpect(jsonPath("$[0].label").value("Renamed"));
    }

    /**
     * Verifies that a label longer than the contract allows is rejected and the passkey keeps its label.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void renamePasskey_whenLabelIsTooLong_isRejected() throws Exception {
        final var user = getFixtures().createUser();
        final var passkey = seedPasskey(user.username(), "Laptop");

        getMockMvc().perform(patch(PASSKEYS_API + "/" + passkey.credentialId()).with(bearerOf(user.username()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"" + "x".repeat(LABEL_TOO_LONG) + "\"}"))
                .andExpect(status().isBadRequest());

        getMockMvc().perform(get(PASSKEYS_API).with(bearerOf(user.username())))
                .andExpect(jsonPath("$[0].label").value("Laptop"));
    }

    /**
     * Verifies that a recent multi-factor sign-in deletes a passkey, and that the passkey is gone from the table and
     * the list while the others stay.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deletePasskey_whenTokenShowsARecentMultiFactorSignIn_removesIt() throws Exception {
        final var user = getFixtures().createUser();
        final var passkey = seedPasskey(user.username(), "Laptop");
        final var kept = seedPasskey(user.username(), "Phone");

        getMockMvc().perform(delete(PASSKEYS_API + "/" + passkey.credentialId()).with(stepUpBearerOf(user.username())))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));

        assertEquals(0, countCredentials(passkey.credentialId()));
        assertEquals(1, countCredentials(kept.credentialId()));
        getMockMvc().perform(get(PASSKEYS_API).with(bearerOf(user.username())))
                .andExpect(jsonPath("$.length()").value(1));
    }

    /**
     * Verifies that an account with a confirmed second factor answers the RFC 9470 challenge to a token that shows
     * no recent multi-factor sign-in (password only, or too old), deletes nothing, and deletes the passkey once the
     * token shows one.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deletePasskey_whenAccountHasASecondFactor_needsARecentMultiFactorSignIn() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var username = enrolled.user().username();
        final var passkey = seedPasskey(username, "Laptop");
        final var path = PASSKEYS_API + "/" + passkey.credentialId();
        final var old = jwt().jwt(token -> token.subject(username)
                .claim(ACR, AuthenticationContextClass.MULTI_FACTOR)
                .claim(AUTH_TIME, Instant.now().minusSeconds(OLD_SIGN_IN_SECONDS).getEpochSecond()));

        for (final var token : List.<RequestPostProcessor>of(bearerOf(username), old)) {
            getMockMvc().perform(delete(path).with(token))
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                            containsString("insufficient_user_authentication")))
                    .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                            containsString(AuthenticationContextClass.MULTI_FACTOR)))
                    .andExpect(jsonPath("$.type").value("urn:problem:mfa:insufficient-user-authentication"));
        }
        assertEquals(1, countCredentials(passkey.credentialId()), "Nothing may be removed without the step-up");

        getMockMvc().perform(delete(path).with(stepUpBearerOf(username))).andExpect(status().isNoContent());
        assertEquals(0, countCredentials(passkey.credentialId()));
    }

    /**
     * Verifies that a passkey is itself a second factor: an account whose only second factor is the passkey it is
     * deleting is asked for a recent multi-factor sign-in too, and nothing is removed.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deletePasskey_whenThePasskeyIsTheOnlySecondFactor_needsARecentMultiFactorSignInToo() throws Exception {
        final var user = getFixtures().createUser();
        final var passkey = seedPasskey(user.username(), "Laptop");

        getMockMvc().perform(delete(PASSKEYS_API + "/" + passkey.credentialId()).with(bearerOf(user.username())))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                        containsString("insufficient_user_authentication")));

        assertEquals(1, countCredentials(passkey.credentialId()));
    }

    /**
     * Verifies that deleting a passkey keeps the trusted devices while another passkey still stands as a second
     * factor, and revokes every one of them once the last passkey (the only second factor) is gone, as disabling the
     * authenticator app does; another account's trusted device is never touched.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deletePasskey_whenTheLastSecondFactorIsDeleted_revokesTheTrustedDevices() throws Exception {
        final var user = getFixtures().createUser();
        final var other = getFixtures().createUser();
        final var userId = idOf(user.username());
        final var otherId = idOf(other.username());
        final var first = seedPasskey(user.username(), "Laptop");
        final var second = seedPasskey(user.username(), "Phone");
        createTrustedDeviceUseCase.execute(userId, user.username(), BROWSER);
        createTrustedDeviceUseCase.execute(otherId, other.username(), BROWSER);

        getMockMvc().perform(delete(PASSKEYS_API + "/" + first.credentialId()).with(stepUpBearerOf(user.username())))
                .andExpect(status().isNoContent());
        assertEquals(1, trustedDevices.findByUser(userId, Instant.now()).size(),
                "A remaining passkey still stands as a second factor");

        getMockMvc().perform(delete(PASSKEYS_API + "/" + second.credentialId()).with(stepUpBearerOf(user.username())))
                .andExpect(status().isNoContent());
        assertEquals(0, trustedDevices.findByUser(userId, Instant.now()).size());
        assertEquals(1, trustedDevices.findByUser(otherId, Instant.now()).size());
        assertEquals(1, getJdbc().sql("SELECT count(*) FROM security_events WHERE user_id = ? AND detail = ?")
                .params(userId, "passkey; trusted devices revoked: 1").query(Long.class).single());
    }

    /**
     * Verifies that a passkey that does not exist, or whose identifier is malformed, is answered as not found or as
     * a bad request.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void passkeys_whenPasskeyDoesNotExist_returnNotFoundProblem() throws Exception {
        final var user = getFixtures().createUser();

        getMockMvc().perform(delete(PASSKEYS_API + "/AQID").with(stepUpBearerOf(user.username())))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value(NOT_FOUND_TYPE));
        getMockMvc().perform(patch(PASSKEYS_API + "/AQID").with(bearerOf(user.username()))
                        .contentType(MediaType.APPLICATION_JSON).content(RENAMED_LABEL))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value(NOT_FOUND_TYPE));
        getMockMvc().perform(delete(PASSKEYS_API + "/not$valid").with(stepUpBearerOf(user.username())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:passkeys:invalid-parameter"));
    }

    /**
     * Verifies the ownership: a passkey of another account is never listed, renamed or deleted, is answered exactly
     * as one that does not exist, and survives untouched.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void passkeys_whenPasskeyBelongsToAnotherAccount_areNeverListedRenamedOrDeleted() throws Exception {
        final var user = getFixtures().createUser();
        final var other = getFixtures().createUser();
        final var own = seedPasskey(user.username(), "Own");
        final var foreign = seedPasskey(other.username(), "Someone else's");
        final var path = PASSKEYS_API + "/" + foreign.credentialId();

        getMockMvc().perform(get(PASSKEYS_API).with(bearerOf(user.username())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(own.credentialId()));
        getMockMvc().perform(patch(path).with(bearerOf(user.username())).contentType(MediaType.APPLICATION_JSON)
                        .content(RENAMED_LABEL))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value(NOT_FOUND_TYPE));
        getMockMvc().perform(delete(path).with(stepUpBearerOf(user.username())))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value(NOT_FOUND_TYPE));

        assertEquals(1, countCredentials(foreign.credentialId()));
        getMockMvc().perform(get(PASSKEYS_API).with(bearerOf(other.username())))
                .andExpect(jsonPath("$[0].label").value("Someone else's"));
    }

    /**
     * Resolves the identifier of an account.
     *
     * @param username name of the account.
     * @return its identifier.
     */
    private UUID idOf(final String username) {
        return userAccounts.findByUsername(username).orElseThrow().id();
    }

    /**
     * Builds the bearer token of a user.
     *
     * @param username the subject of the token.
     * @return the request post-processor.
     */
    private static RequestPostProcessor bearerOf(final String username) {
        return jwt().jwt(token -> token.subject(username));
    }

    /**
     * Builds the bearer token of a user who signed in with a second factor just now.
     *
     * @param username the subject of the token.
     * @return the request post-processor.
     */
    private static RequestPostProcessor stepUpBearerOf(final String username) {
        return jwt().jwt(token -> token.subject(username)
                .claim(ACR, AuthenticationContextClass.MULTI_FACTOR)
                .claim(AUTH_TIME, Instant.now().getEpochSecond()));
    }
}
