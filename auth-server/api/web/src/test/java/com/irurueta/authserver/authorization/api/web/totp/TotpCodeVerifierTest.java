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
package com.irurueta.authserver.authorization.api.web.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.totp.ConfirmTotpAtSignInUseCase;
import com.irurueta.authserver.authorization.application.totp.VerifyRecoveryCodeUseCase;
import com.irurueta.authserver.authorization.application.totp.VerifyTotpUseCase;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Unit tests of {@link TotpCodeVerifier}.
 */
@ExtendWith(MockitoExtension.class)
class TotpCodeVerifierTest {

    /** The user. */
    private static final String USERNAME = "alice";

    /** The code. */
    private static final String CODE = "123456";

    /** Identifier of the account. */
    private static final UUID USER_ID = UUID.randomUUID();

    /** Verifies TOTP codes. */
    @Mock
    private VerifyTotpUseCase verifyTotpUseCase;

    /** Verifies recovery codes. */
    @Mock
    private VerifyRecoveryCodeUseCase verifyRecoveryCodeUseCase;

    /** Confirms enrolments. */
    @Mock
    private ConfirmTotpAtSignInUseCase confirmTotpAtSignInUseCase;

    /** Verifier under test. */
    @InjectMocks
    private TotpCodeVerifier verifier;

    /** The authentication the user already holds. */
    private final Authentication primary =
            UsernamePasswordAuthenticationToken.authenticated(USERNAME, "secret", List.of());

    /**
     * Verifies that a TOTP code goes to the TOTP use case.
     */
    @Test
    void verify_whenCodeIsTotp_usesTheTotpUseCase() {
        when(verifyTotpUseCase.execute(USER_ID, USERNAME, CODE)).thenReturn(true);

        assertTrue(verifier.verify(request(TotpCodeKind.TOTP), USER_ID, USERNAME));
        verifyNoInteractions(verifyRecoveryCodeUseCase, confirmTotpAtSignInUseCase);
    }

    /**
     * Verifies that a recovery code goes to the recovery use case.
     */
    @Test
    void verify_whenCodeIsRecovery_usesTheRecoveryUseCase() {
        when(verifyRecoveryCodeUseCase.execute(USER_ID, USERNAME, CODE)).thenReturn(false);

        assertFalse(verifier.verify(request(TotpCodeKind.RECOVERY), USER_ID, USERNAME));
        verifyNoInteractions(verifyTotpUseCase, confirmTotpAtSignInUseCase);
    }

    /**
     * Verifies that a confirmed enrolment hands the new recovery codes back through the request.
     */
    @Test
    void verify_whenEnrolmentIsConfirmed_issuesTheRecoveryCodes() {
        final var request = request(TotpCodeKind.ENROLMENT);
        when(confirmTotpAtSignInUseCase.execute(USER_ID, USERNAME, CODE))
                .thenReturn(Optional.of(List.of("AAAAAAAAAA")));

        assertTrue(verifier.verify(request, USER_ID, USERNAME));
        assertEquals(List.of("AAAAAAAAAA"), request.issuedRecoveryCodes());
    }

    /**
     * Verifies that a wrong enrolment code is refused and issues nothing.
     */
    @Test
    void verify_whenEnrolmentCodeIsWrong_returnsFalse() {
        final var request = request(TotpCodeKind.ENROLMENT);
        when(confirmTotpAtSignInUseCase.execute(USER_ID, USERNAME, CODE)).thenReturn(Optional.empty());

        assertFalse(verifier.verify(request, USER_ID, USERNAME));
        assertTrue(request.issuedRecoveryCodes().isEmpty());
    }

    /**
     * Builds a verification request.
     *
     * @param kind the kind of code.
     * @return the request.
     */
    private TotpAuthenticationToken request(final TotpCodeKind kind) {
        return new TotpAuthenticationToken(primary, CODE, kind);
    }
}
