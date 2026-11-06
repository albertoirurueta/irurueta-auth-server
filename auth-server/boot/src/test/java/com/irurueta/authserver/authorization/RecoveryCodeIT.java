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

import com.irurueta.authserver.authorization.application.totp.GenerateRecoveryCodesUseCase;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks that a recovery code stands in for the authenticator app code exactly once.
 */
class RecoveryCodeIT extends AbstractMfaFlow {

    /** Port that stores the recovery codes. */
    @Autowired
    private RecoveryCodeRepository recoveryCodes;

    /**
     * Verifies that a recovery code completes the sign-in, is spent, and is refused the second time.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenRecoveryCodeIsUsedTwice_isAcceptedOnlyOnce() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var code = enrolled.recoveryCodes().getFirst();
        final var client = getFixtures().createMfaCodeClient();

        final var first = new MockHttpSession();
        final var verifier = newVerifier();
        final var firstUri = signInForAuthorization(enrolled.user(), client, verifier, Map.of(), first);
        final var accepted = postSecondFactor(first, code, true, false);
        assertAccepted(accepted);
        final var tokens = completeAuthorization(firstUri, client, verifier, first);
        assertEquals("urn:irurueta:acr:mfa",
                AuthServerFixtures.claimsOf(tokens.get("access_token").asString()).get("acr").asString());
        assertEquals(GenerateRecoveryCodesUseCase.CODE_COUNT - 1, recoveryCodes.findUnused(enrolled.id()).size());

        final var second = new MockHttpSession();
        signInForAuthorization(enrolled.user(), client, newVerifier(), Map.of(), second);
        final var refused = postSecondFactor(second, code, true, false);
        assertTrue(refused.getResponse().getRedirectedUrl().endsWith("/login/second-factor?error"));
    }
}
