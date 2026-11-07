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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.application.mfa.CreateTrustedDeviceUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Checks the phone endpoints of the account API against the real application: while the account has a confirmed
 * second factor, replacing the phone needs a recent multi-factor sign-in as removing it does; replacing or removing a
 * verified phone is audited and revokes the trusted devices the old factor stood behind; and a number another user
 * verified meanwhile is refused as an invalid code, never as a server error. The requests carry a {@code jwt()} for
 * the owner of the account; the verification SMS is read from the logging sender.
 */
class PhoneApiIT extends AbstractOttFlow {

    /** Path of the phone endpoint. */
    private static final String PHONE_PATH = "/api/account/phone";

    /** Path of the verification endpoint. */
    private static final String VERIFY_PATH = PHONE_PATH + "/verify";

    /** The RFC 9470 challenge of an operation that needs a recent multi-factor sign-in. */
    private static final String STEP_UP_CHALLENGE = "Bearer error=\"insufficient_user_authentication\", "
            + "acr_values=\"urn:irurueta:acr:mfa\", max_age=\"300\"";

    /** Prefix of the generated Spanish mobile numbers. */
    private static final String SPANISH_PREFIX = "+346";

    /** Port that stores user accounts. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores the verified phones. */
    @Autowired
    private UserPhoneRepository phones;

    /** Port that stores the trusted devices. */
    @Autowired
    private TrustedDeviceRepository trustedDevices;

    /** Use case that trusts a device. */
    @Autowired
    private CreateTrustedDeviceUseCase createTrustedDeviceUseCase;

    /** Reads the audit events. */
    @Autowired
    private JdbcClient jdbc;

    /**
     * Verifies that an account without any second factor enrols its first phone with a password-only token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void startPhoneEnrolment_whenAccountHasNoSecondFactor_needsNoStepUp() throws Exception {
        final var user = getFixtures().createUser();
        final var phone = newPhone();

        getMockMvc().perform(enrol(phone).with(bearerOf(user.username()))).andExpect(status().isAccepted());

        assertEquals(1L, awaitSmsCount(phone, 1L));
    }

    /**
     * Verifies that an account with a verified phone cannot start replacing it with a password-only token: the
     * challenge is answered and no message is sent to the new number.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void startPhoneEnrolment_whenAccountHasAPhoneAndTokenIsPasswordOnly_answersTheStepUpChallenge() throws Exception {
        final var owner = createUserWithPhone();
        final var replacement = newPhone();

        getMockMvc().perform(enrol(replacement).with(bearerOf(owner.user().username())))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", STEP_UP_CHALLENGE))
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:insufficient-user-authentication"));

        assertEquals(0L, smsCount(replacement));
        assertEquals(owner.phone(), phones.findByUserId(idOf(owner.user().username())).orElseThrow().phone());
    }

    /**
     * Verifies that, after a recent multi-factor sign-in, the phone is replaced: the code sent to the new number
     * confirms it, the trusted devices are revoked and the replacement is audited.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void verifyPhone_whenANewNumberReplacesTheVerifiedOne_revokesTrustedDevicesAndAudits() throws Exception {
        final var owner = createUserWithPhone();
        final var username = owner.user().username();
        final var userId = idOf(username);
        createTrustedDeviceUseCase.execute(userId, username, "Firefox on Linux");
        final var replacement = newPhone();

        getMockMvc().perform(enrol(replacement).with(stepUpBearerOf(username))).andExpect(status().isAccepted());
        getMockMvc().perform(verify(lastSmsCode(replacement)).with(stepUpBearerOf(username)))
                .andExpect(status().isOk());

        assertEquals(replacement, phones.findByUserId(userId).orElseThrow().phone());
        assertTrue(trustedDevices.findByUser(userId, Instant.now()).isEmpty());
        assertEquals(1L, removalEvents(userId));
    }

    /**
     * Verifies that removing the phone that was the only second factor revokes the trusted devices and is audited.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void removePhone_whenItWasTheOnlySecondFactor_revokesTrustedDevicesAndAudits() throws Exception {
        final var owner = createUserWithPhone();
        final var username = owner.user().username();
        final var userId = idOf(username);
        createTrustedDeviceUseCase.execute(userId, username, "Firefox on Linux");

        getMockMvc().perform(delete(PHONE_PATH).with(stepUpBearerOf(username))).andExpect(status().isNoContent());

        assertTrue(phones.findByUserId(userId).isEmpty());
        assertTrue(trustedDevices.findByUser(userId, Instant.now()).isEmpty());
        assertEquals(1L, removalEvents(userId));
    }

    /**
     * Verifies that a number another user verified meanwhile is refused as an invalid code, not as a server error,
     * and stays the other user's.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void verifyPhone_whenAnotherUserVerifiedTheNumberMeanwhile_answersInvalidCode() throws Exception {
        final var first = getFixtures().createUser();
        final var second = getFixtures().createUser();
        final var phone = newPhone();
        getMockMvc().perform(enrol(phone).with(bearerOf(first.username()))).andExpect(status().isAccepted());
        final var firstCode = lastSmsCode(phone);
        getMockMvc().perform(enrol(phone).with(bearerOf(second.username()))).andExpect(status().isAccepted());
        awaitSmsCount(phone, 2L);
        final var secondCode = lastSmsCode(phone);
        getMockMvc().perform(verify(firstCode).with(bearerOf(first.username()))).andExpect(status().isOk());

        getMockMvc().perform(verify(secondCode).with(bearerOf(second.username())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:phone:invalid-code"));

        assertEquals(idOf(first.username()), phones.findByPhone(phone).orElseThrow().userId());
    }

    /**
     * Builds the request that starts the enrolment of a number.
     *
     * @param phone the number.
     * @return the request.
     */
    private static MockHttpServletRequestBuilder enrol(final PhoneNumber phone) {
        return put(PHONE_PATH).contentType(MediaType.APPLICATION_JSON).content("{\"phone\":\"" + phone.e164() + "\"}");
    }

    /**
     * Builds the request that confirms the pending number with a code.
     *
     * @param code the code.
     * @return the request.
     */
    private static MockHttpServletRequestBuilder verify(final String code) {
        return post(VERIFY_PATH).contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"" + code + "\"}");
    }

    /**
     * Generates a Spanish mobile number nobody holds.
     *
     * @return the number.
     */
    private static PhoneNumber newPhone() {
        return new PhoneNumber(SPANISH_PREFIX + digits());
    }

    /**
     * Builds the bearer token of a user who signed in with a password only.
     *
     * @param username the user, the subject of the token.
     * @return the request post-processor.
     */
    private static RequestPostProcessor bearerOf(final String username) {
        return jwt().jwt(token -> token.subject(username));
    }

    /**
     * Builds the bearer token of a user who signed in with a second factor just now.
     *
     * @param username the user, the subject of the token.
     * @return the request post-processor.
     */
    private static RequestPostProcessor stepUpBearerOf(final String username) {
        return jwt().jwt(token -> token.subject(username)
                .claim("acr", AuthenticationContextClass.MULTI_FACTOR)
                .claim("auth_time", Instant.now().getEpochSecond()));
    }

    /**
     * Gets the identifier of a user.
     *
     * @param username the name of the user.
     * @return its account identifier.
     */
    private UUID idOf(final String username) {
        return userAccounts.findByUsername(username).orElseThrow().id();
    }

    /**
     * Counts the audit events of a removed second factor of a user.
     *
     * @param userId identifier of the user.
     * @return the number of events.
     */
    private long removalEvents(final UUID userId) {
        return jdbc.sql("SELECT count(*) FROM security_events WHERE user_id = ? AND type = ?")
                .params(userId, SecurityEventType.SECOND_FACTOR_REMOVED.name()).query(Long.class).single();
    }
}
