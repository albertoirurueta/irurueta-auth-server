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

package com.irurueta.authserver.authorization.application.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.CheckSecondFactorLockoutUseCase;
import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.application.mfa.RegisterSecondFactorFailureUseCase;
import com.irurueta.authserver.authorization.application.mfa.ResetSecondFactorFailuresUseCase;
import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCode;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeHasher;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeRepository;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link VerifyOneTimeCodeUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class VerifyOneTimeCodeUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Binding used by the tests. */
    private static final String BINDING = "session-1";

    /** Code typed by the user. */
    private static final String CODE = "123456";

    /** Stored hash. */
    private static final String HASH = "stored-hash";

    /** Maximum attempts of the policy. */
    private static final int MAX_ATTEMPTS = 3;

    /** Identifier of the stored code. */
    private static final UUID CODE_ID = UUID.randomUUID();

    /** Identifier of the user. */
    private static final UUID USER_ID = UUID.randomUUID();

    /** Every channel, as a sign-in accepts. */
    private static final Set<OttChannel> ALL = EnumSet.allOf(OttChannel.class);

    /** Port that stores the codes. */
    @Mock
    private OneTimeCodeRepository oneTimeCodeRepository;

    /** Hasher of codes. */
    @Mock
    private OneTimeCodeHasher oneTimeCodeHasher;

    /** Real policy of the codes. */
    @Spy
    private OttPolicy ottPolicy = new OttPolicy(6, Duration.ofMinutes(10), Duration.ofMinutes(15), MAX_ATTEMPTS);

    /** Use case that finds the account. */
    @Mock
    private FindUserAccountUseCase findUserAccountUseCase;

    /** Use case that checks the lockout. */
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

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private VerifyOneTimeCodeUseCase useCase;

    /**
     * Verifies that a correct login code is accepted once, with its channel, and no lockout machinery is used.
     */
    @Test
    void execute_whenLoginCodeIsCorrect_returnsSuccess() {
        stubActive(OttPurpose.LOGIN);
        when(oneTimeCodeRepository.incrementAttempts(CODE_ID)).thenReturn(1);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(true);
        when(oneTimeCodeRepository.consume(CODE_ID)).thenReturn(true);

        final var result = useCase.execute(BINDING, USERNAME, CODE, OttPurpose.LOGIN, ALL);

        assertTrue(result.isSuccess());
        assertEquals(OttChannel.EMAIL, result.channel());
        verifyNoInteractions(checkSecondFactorLockoutUseCase, registerSecondFactorFailureUseCase,
                resetSecondFactorFailuresUseCase, recordSecurityEventUseCase, findUserAccountUseCase);
    }

    /**
     * Verifies that two concurrent submissions of a correct code accept only one: the loser's consume fails.
     */
    @Test
    void execute_whenConsumeLosesTheRace_returnsFailure() {
        stubActive(OttPurpose.LOGIN);
        when(oneTimeCodeRepository.incrementAttempts(CODE_ID)).thenReturn(1);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(true);
        when(oneTimeCodeRepository.consume(CODE_ID)).thenReturn(false);

        assertEquals(OttVerificationResult.failure(), useCase.execute(BINDING, USERNAME, CODE, OttPurpose.LOGIN, ALL));
    }

    /**
     * Verifies that an unknown, expired or used code fails without counting an attempt.
     */
    @Test
    void execute_whenNoActiveCode_returnsFailure() {
        when(clock.instant()).thenReturn(NOW);
        when(oneTimeCodeRepository.findActive(BINDING, USERNAME, NOW)).thenReturn(Optional.empty());

        assertEquals(OttVerificationResult.failure(), useCase.execute(BINDING, USERNAME, CODE, OttPurpose.LOGIN, ALL));

        verify(oneTimeCodeRepository, never()).incrementAttempts(CODE_ID);
    }

    /**
     * Verifies that a code issued for another purpose is refused without counting an attempt.
     */
    @Test
    void execute_whenPurposeDiffers_returnsFailure() {
        stubActive(OttPurpose.SECOND_FACTOR);

        assertEquals(OttVerificationResult.failure(), useCase.execute(BINDING, USERNAME, CODE, OttPurpose.LOGIN, ALL));

        verify(oneTimeCodeRepository, never()).incrementAttempts(CODE_ID);
    }

    /**
     * Verifies that a wrong code below the limit fails and leaves the code usable.
     */
    @Test
    void execute_whenCodeIsWrongBelowLimit_returnsFailureWithoutBurning() {
        stubActive(OttPurpose.LOGIN);
        when(oneTimeCodeRepository.incrementAttempts(CODE_ID)).thenReturn(1);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(false);

        assertEquals(OttVerificationResult.failure(), useCase.execute(BINDING, USERNAME, CODE, OttPurpose.LOGIN, ALL));

        verify(oneTimeCodeRepository, never()).consume(CODE_ID);
    }

    /**
     * Verifies that the last wrong attempt burns the code.
     */
    @Test
    void execute_whenLastAttemptIsWrong_burnsTheCode() {
        stubActive(OttPurpose.LOGIN);
        when(oneTimeCodeRepository.incrementAttempts(CODE_ID)).thenReturn(MAX_ATTEMPTS);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(false);

        assertEquals(OttVerificationResult.failure(), useCase.execute(BINDING, USERNAME, CODE, OttPurpose.LOGIN, ALL));

        verify(oneTimeCodeRepository).consume(CODE_ID);
    }

    /**
     * Verifies that the last allowed attempt still accepts a correct code.
     */
    @Test
    void execute_whenLastAttemptIsCorrect_returnsSuccess() {
        stubActive(OttPurpose.LOGIN);
        when(oneTimeCodeRepository.incrementAttempts(CODE_ID)).thenReturn(MAX_ATTEMPTS);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(true);
        when(oneTimeCodeRepository.consume(CODE_ID)).thenReturn(true);

        assertTrue(useCase.execute(BINDING, USERNAME, CODE, OttPurpose.LOGIN, ALL).isSuccess());
    }

    /**
     * Verifies that a counter already past the limit (concurrent attempts) burns the code without comparing.
     */
    @Test
    void execute_whenAttemptsExceedLimit_burnsWithoutComparing() {
        stubActive(OttPurpose.LOGIN);
        when(oneTimeCodeRepository.incrementAttempts(CODE_ID)).thenReturn(MAX_ATTEMPTS + 1);

        assertEquals(OttVerificationResult.failure(), useCase.execute(BINDING, USERNAME, CODE, OttPurpose.LOGIN, ALL));

        verify(oneTimeCodeRepository).consume(CODE_ID);
        verifyNoInteractions(oneTimeCodeHasher);
    }

    /**
     * Verifies that a locked second factor is reported before anything is compared.
     */
    @Test
    void execute_whenSecondFactorIsLocked_returnsLocked() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account()));
        when(checkSecondFactorLockoutUseCase.execute(USER_ID)).thenReturn(true);

        assertEquals(OttVerificationResult.locked(),
                useCase.execute(BINDING, USERNAME, CODE, OttPurpose.SECOND_FACTOR, ALL));

        verifyNoInteractions(oneTimeCodeRepository, oneTimeCodeHasher);
    }

    /**
     * Verifies that an unknown user fails a second-factor verification without touching the lockout.
     */
    @Test
    void execute_whenSecondFactorUserIsUnknown_returnsFailure() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.empty());

        assertEquals(OttVerificationResult.failure(),
                useCase.execute(BINDING, USERNAME, CODE, OttPurpose.SECOND_FACTOR, ALL));

        verifyNoInteractions(checkSecondFactorLockoutUseCase, oneTimeCodeRepository);
    }

    /**
     * Verifies that a correct second-factor code clears the failures and is audited.
     */
    @Test
    void execute_whenSecondFactorCodeIsCorrect_resetsFailuresAndRecordsSuccess() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account()));
        when(checkSecondFactorLockoutUseCase.execute(USER_ID)).thenReturn(false);
        stubActive(OttPurpose.SECOND_FACTOR);
        when(oneTimeCodeRepository.incrementAttempts(CODE_ID)).thenReturn(1);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(true);
        when(oneTimeCodeRepository.consume(CODE_ID)).thenReturn(true);

        final var result = useCase.execute(BINDING, USERNAME, CODE, OttPurpose.SECOND_FACTOR, ALL);

        assertTrue(result.isSuccess());
        verify(resetSecondFactorFailuresUseCase).execute(USER_ID);
        verify(recordSecurityEventUseCase).execute(SecurityEventType.SECOND_FACTOR_SUCCESS, USER_ID, USERNAME,
                "one-time code");
        verify(registerSecondFactorFailureUseCase, never()).execute(USER_ID, USERNAME);
    }

    /**
     * Verifies that a second-factor code of a channel the caller does not accept (the e-mail code of the stubs, for a
     * user who may only use SMS) is burnt without being compared, counted against the lockout and never audited as a
     * success, even though it is the right code.
     */
    @Test
    void execute_whenSecondFactorCodeChannelIsNotAccepted_burnsItAndRegistersFailure() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account()));
        when(checkSecondFactorLockoutUseCase.execute(USER_ID)).thenReturn(false);
        stubActive(OttPurpose.SECOND_FACTOR);

        final var result = useCase.execute(BINDING, USERNAME, CODE, OttPurpose.SECOND_FACTOR,
                EnumSet.of(OttChannel.SMS));

        assertEquals(OttVerificationResult.failure(), result);
        verify(oneTimeCodeRepository).consume(CODE_ID);
        verify(oneTimeCodeRepository, never()).incrementAttempts(CODE_ID);
        verifyNoInteractions(oneTimeCodeHasher, resetSecondFactorFailuresUseCase, recordSecurityEventUseCase);
        verify(registerSecondFactorFailureUseCase).execute(USER_ID, USERNAME);
    }

    /**
     * Verifies that a wrong second-factor code is counted against the lockout.
     */
    @Test
    void execute_whenSecondFactorCodeIsWrong_registersFailure() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account()));
        when(checkSecondFactorLockoutUseCase.execute(USER_ID)).thenReturn(false);
        stubActive(OttPurpose.SECOND_FACTOR);
        when(oneTimeCodeRepository.incrementAttempts(CODE_ID)).thenReturn(1);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(false);

        final var result = useCase.execute(BINDING, USERNAME, CODE, OttPurpose.SECOND_FACTOR, ALL);

        assertEquals(OttVerificationResult.failure(), result);
        verify(registerSecondFactorFailureUseCase).execute(USER_ID, USERNAME);
        verify(resetSecondFactorFailuresUseCase, never()).execute(USER_ID);
    }

    /**
     * Stubs the lookup of an active code of a purpose.
     *
     * @param purpose purpose of the stored code.
     */
    private void stubActive(final OttPurpose purpose) {
        when(clock.instant()).thenReturn(NOW);
        when(oneTimeCodeRepository.findActive(BINDING, USERNAME, NOW)).thenReturn(Optional.of(new OneTimeCode(
                CODE_ID, USERNAME, OttChannel.EMAIL, purpose, HASH, BINDING, 0, NOW.plusSeconds(1), NOW)));
    }

    /**
     * Builds the account of the user.
     *
     * @return the account.
     */
    private static UserAccount account() {
        return new UserAccount(USER_ID, USERNAME, "encoded", true, List.of());
    }
}
