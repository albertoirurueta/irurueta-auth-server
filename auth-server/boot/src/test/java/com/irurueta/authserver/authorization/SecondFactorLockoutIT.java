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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.application.mfa.MfaProperties;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorAttemptRepository;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventRepository;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks that repeated wrong second-factor codes lock the second factor: not even the right code is accepted while
 * it is locked, and the failures are recorded as security events.
 */
class SecondFactorLockoutIT extends AbstractMfaFlow {

    /** Number of recent events read back. */
    private static final int EVENTS = 50;

    /** Settings of the multi-factor authentication. */
    @Autowired
    private MfaProperties mfaProperties;

    /** Port that stores the failed attempts. */
    @Autowired
    private SecondFactorAttemptRepository attempts;

    /** Port that stores the security events. */
    @Autowired
    private SecurityEventRepository securityEvents;

    /** Port that stores user accounts. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores the authenticator app credentials. */
    @Autowired
    private TotpCredentialRepository totpCredentials;

    /**
     * Verifies that the configured number of failures locks the second factor, even against the right code.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenTooManyCodesFail_locksTheSecondFactor() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var client = getFixtures().createMfaCodeClient();
        final var session = new MockHttpSession();
        signInForAuthorization(enrolled.user(), client, newVerifier(), Map.of(), session);

        for (var attempt = 0; attempt < mfaProperties.maxFailedAttempts(); attempt++) {
            final var failed = postSecondFactor(session, getTools().wrongCode(enrolled.id()), false, false);
            assertTrue(failed.getResponse().getRedirectedUrl().endsWith("?error"));
        }
        final var locked = postSecondFactor(session, getTools().codeNow(enrolled.id(), 0), false, false);

        assertTrue(locked.getResponse().getRedirectedUrl().endsWith("?error"), "The right code must be refused");
        assertTrue(attempts.find(enrolled.id()).isLocked(Instant.now()));
        assertTrue(securityEvents.findRecentByUser(enrolled.id(), EVENTS).stream()
                .anyMatch(event -> event.type() == SecurityEventType.SECOND_FACTOR_FAILURE));
    }

    /**
     * Verifies that wrong codes posted to confirm an enrolment during the sign-in count towards the same lockout, so
     * the enrolment form cannot be used to guess codes, and that the right code is refused once locked.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void enrolment_whenTooManyCodesFail_locksTheSecondFactor() throws Exception {
        final var user = getFixtures().createUser();
        getFixtures().requireMfa(user, getTools());
        final var userId = userAccounts.findByUsername(user.username()).orElseThrow().id();
        final var session = new MockHttpSession();
        signInForAuthorization(user, getFixtures().createCodeClient(), newVerifier(), Map.of(), session);
        secondFactorPage(session);

        for (var attempt = 0; attempt < mfaProperties.maxFailedAttempts(); attempt++) {
            final var failed = postEnrolment(session, getTools().wrongCode(userId));
            assertTrue(failed.getResponse().getRedirectedUrl().endsWith("?error"));
        }
        final var locked = postEnrolment(session, getTools().codeNow(userId, 0));

        assertTrue(locked.getResponse().getRedirectedUrl().endsWith("?error"), "The right code must be refused");
        assertTrue(attempts.find(userId).isLocked(Instant.now()));
        assertFalse(totpCredentials.findByUser(userId).orElseThrow().confirmed());
    }
}
