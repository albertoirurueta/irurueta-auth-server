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
package com.irurueta.authserver.authorization.application.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.CheckSecondFactorLockoutUseCase;
import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.application.mfa.RegisterSecondFactorFailureUseCase;
import com.irurueta.authserver.authorization.application.mfa.ResetSecondFactorFailuresUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockedException;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ConfirmTotpAtSignInUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ConfirmTotpAtSignInUseCaseTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Code typed by the user. */
    private static final String CODE = "123456";

    /** Use case that confirms the enrolment. */
    @Mock
    private ConfirmTotpUseCase confirmTotpUseCase;

    /** Use case that tells whether the second factor is locked. */
    @Mock
    private CheckSecondFactorLockoutUseCase checkSecondFactorLockoutUseCase;

    /** Use case that counts a failure. */
    @Mock
    private RegisterSecondFactorFailureUseCase registerSecondFactorFailureUseCase;

    /** Use case that clears the failures. */
    @Mock
    private ResetSecondFactorFailuresUseCase resetSecondFactorFailuresUseCase;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Use case under test. */
    @InjectMocks
    private ConfirmTotpAtSignInUseCase useCase;

    /**
     * Verifies that a right code confirms the enrolment, clears the failures, is audited and answers the codes.
     */
    @Test
    void execute_whenCodeIsRight_returnsTheRecoveryCodesAndClearsTheFailures() {
        final var userId = UUID.randomUUID();
        final var codes = List.of("AAAAAAAAAA");
        when(checkSecondFactorLockoutUseCase.execute(userId)).thenReturn(false);
        when(confirmTotpUseCase.tryConfirm(userId, CODE)).thenReturn(Optional.of(codes));

        assertEquals(Optional.of(codes), useCase.execute(userId, USERNAME, CODE));

        verify(resetSecondFactorFailuresUseCase).execute(userId);
        verify(recordSecurityEventUseCase).execute(SecurityEventType.SECOND_FACTOR_SUCCESS, userId, USERNAME,
                "totp enrolment");
        verify(registerSecondFactorFailureUseCase, never()).execute(userId, USERNAME);
    }

    /**
     * Verifies that a wrong code answers nothing and counts a failure.
     */
    @Test
    void execute_whenCodeIsWrong_returnsEmptyAndCountsTheFailure() {
        final var userId = UUID.randomUUID();
        when(checkSecondFactorLockoutUseCase.execute(userId)).thenReturn(false);
        when(confirmTotpUseCase.tryConfirm(userId, CODE)).thenReturn(Optional.empty());

        assertTrue(useCase.execute(userId, USERNAME, CODE).isEmpty());

        verify(registerSecondFactorFailureUseCase).execute(userId, USERNAME);
        verifyNoInteractions(resetSecondFactorFailuresUseCase, recordSecurityEventUseCase);
    }

    /**
     * Verifies that a locked second factor is refused before the code is looked at.
     */
    @Test
    void execute_whenLocked_throwsSecondFactorLockedException() {
        final var userId = UUID.randomUUID();
        when(checkSecondFactorLockoutUseCase.execute(userId)).thenReturn(true);

        assertThrows(SecondFactorLockedException.class, () -> useCase.execute(userId, USERNAME, CODE));

        verifyNoInteractions(confirmTotpUseCase, registerSecondFactorFailureUseCase);
    }
}
