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

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.api.web.mfa.MfaProperties;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorAttemptRepository;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventRepository;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
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
}
