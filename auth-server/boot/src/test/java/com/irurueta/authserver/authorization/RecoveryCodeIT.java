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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.application.totp.CountRecoveryCodesUseCase;
import com.irurueta.authserver.authorization.application.totp.GenerateRecoveryCodesUseCase;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks that a recovery code stands in for the authenticator app code exactly once, and that the second-factor page
 * warns when few recovery codes are left.
 */
class RecoveryCodeIT extends AbstractMfaFlow {

    /** Text of the warning shown when few recovery codes are left, after the count. */
    private static final String LOW_CODES_WARNING = "recovery codes are left";

    /** Port that stores the recovery codes. */
    @Autowired
    private RecoveryCodeRepository recoveryCodes;

    /** Port that stores the TOTP credentials. */
    @Autowired
    private TotpCredentialRepository totpCredentials;

    /**
     * Verifies that a recovery code is refused, and not spent, when the account no longer has a confirmed second
     * factor: recovery codes only stand in for one.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenNoSecondFactorIsConfirmed_refusesTheRecoveryCode() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var code = enrolled.recoveryCodes().getFirst();
        final var client = getFixtures().createMfaCodeClient();
        final var session = new MockHttpSession();
        signInForAuthorization(enrolled.user(), client, newVerifier(), Map.of(), session);
        totpCredentials.deleteByUser(enrolled.id());

        final var refused = postSecondFactor(session, code, true, false);

        assertTrue(refused.getResponse().getRedirectedUrl().endsWith("/login/second-factor?error"));
        assertEquals(GenerateRecoveryCodesUseCase.CODE_COUNT, recoveryCodes.findUnused(enrolled.id()).size());
    }

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

    /**
     * Verifies that the second-factor page warns, with the count, once only
     * {@value CountRecoveryCodesUseCase#LOW_THRESHOLD} recovery codes are left, and not before.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactorPage_whenFewRecoveryCodesAreLeft_warnsWithTheCount() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var client = getFixtures().createMfaCodeClient();
        final var session = new MockHttpSession();
        signInForAuthorization(enrolled.user(), client, newVerifier(), Map.of(), session);
        final var unused = recoveryCodes.findUnused(enrolled.id());
        final var toSpend = unused.size() - CountRecoveryCodesUseCase.LOW_THRESHOLD;
        unused.stream().limit(toSpend - 1L).forEach(code -> recoveryCodes.markUsed(code.id(), Instant.now()));
        assertFalse(secondFactorPage(session).contains(LOW_CODES_WARNING));

        recoveryCodes.markUsed(unused.get(toSpend - 1).id(), Instant.now());

        assertTrue(secondFactorPage(session).contains(
                "Only " + CountRecoveryCodesUseCase.LOW_THRESHOLD + " " + LOW_CODES_WARNING));
    }
}
