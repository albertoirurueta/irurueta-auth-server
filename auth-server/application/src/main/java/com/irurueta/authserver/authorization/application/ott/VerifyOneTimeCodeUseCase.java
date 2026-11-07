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
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Verifies a one-time code.
 *
 * <p>A code is checked at most {@link OttPolicy#maxAttempts()} times: the attempt counter is incremented atomically
 * before the comparison, and the code is burnt (consumed) after the last wrong attempt or when the counter is already
 * past the limit. A correct code is accepted once: consuming it must succeed, so of two concurrent submissions of the
 * same code only one is accepted. Wrong, expired, burnt, already used and mismatching-purpose codes all give the same
 * {@link OttVerificationResult#failure()}. So does a code delivered through a channel the caller does not accept (for a
 * second factor, the channel that signed the user in, or e-mail for a user with another confirmed second factor): it is
 * burnt and, as a second factor, counted against the lockout and never audited as a success.
 *
 * <p>For {@link OttPurpose#SECOND_FACTOR} the shared second-factor lockout applies exactly as for TOTP: it is checked
 * first (a locked user gets {@link OttVerificationResult#locked()} and nothing is compared), every failure is
 * counted, and a success clears the counter and is audited. A {@link OttPurpose#LOGIN} code is not counted: the
 * framework's own authentication events audit it.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class VerifyOneTimeCodeUseCase {

    /** Detail stored in the audit event of an accepted code. */
    private static final String AUDIT_DETAIL = "one-time code";

    /** Port that stores the codes. */
    private final OneTimeCodeRepository oneTimeCodeRepository;

    /** Hasher of codes. */
    private final OneTimeCodeHasher oneTimeCodeHasher;

    /** Policy of the codes. */
    private final OttPolicy ottPolicy;

    /** Use case that finds the account of the user. */
    private final FindUserAccountUseCase findUserAccountUseCase;

    /** Use case that tells whether the second factor is locked (and serializes the attempts of a user). */
    private final CheckSecondFactorLockoutUseCase checkSecondFactorLockoutUseCase;

    /** Use case that counts a failure. */
    private final RegisterSecondFactorFailureUseCase registerSecondFactorFailureUseCase;

    /** Use case that clears the failures. */
    private final ResetSecondFactorFailuresUseCase resetSecondFactorFailuresUseCase;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Verifies a code.
     *
     * @param bindingId identifier of the sign-in attempt the code was bound to.
     * @param username  name of the user.
     * @param code      the code as typed.
     * @param purpose   what the code is for.
     * @param channels  the channels whose codes are accepted; a code of any other channel is a failure.
     * @return the outcome.
     */
    public OttVerificationResult execute(final String bindingId, final String username, final String code,
            final OttPurpose purpose, final Set<OttChannel> channels) {
        if (purpose != OttPurpose.SECOND_FACTOR) {
            return check(bindingId, username, code, purpose, channels);
        }
        final var account = findUserAccountUseCase.execute(username).orElse(null);
        if (account == null) {
            return OttVerificationResult.failure();
        }
        final var userId = account.id();
        if (checkSecondFactorLockoutUseCase.execute(userId)) {
            return OttVerificationResult.locked();
        }
        final var result = check(bindingId, username, code, purpose, channels);
        recordSecondFactorOutcome(result, account);
        return result;
    }

    /**
     * Counts the outcome of a second-factor verification.
     *
     * @param result  the outcome.
     * @param account the account of the user.
     */
    private void recordSecondFactorOutcome(final OttVerificationResult result, final UserAccount account) {
        final UUID userId = account.id();
        if (result.isSuccess()) {
            resetSecondFactorFailuresUseCase.execute(userId);
            recordSecurityEventUseCase.execute(SecurityEventType.SECOND_FACTOR_SUCCESS, userId, account.username(),
                    AUDIT_DETAIL);
        } else {
            registerSecondFactorFailureUseCase.execute(userId, account.username());
        }
    }

    /**
     * Checks a code against the active one, counting the attempt.
     *
     * @param bindingId identifier of the sign-in attempt.
     * @param username  name of the user.
     * @param code      the code as typed.
     * @param purpose   what the code is for.
     * @param channels  the channels whose codes are accepted.
     * @return success when the code is valid and was consumed, failure otherwise.
     */
    private OttVerificationResult check(final String bindingId, final String username, final String code,
            final OttPurpose purpose, final Set<OttChannel> channels) {
        final var active = oneTimeCodeRepository.findActive(bindingId, username, clock.instant())
                .filter(stored -> stored.purpose() == purpose)
                .orElse(null);
        if (active == null) {
            return OttVerificationResult.failure();
        }
        if (!channels.contains(active.channel())) {
            oneTimeCodeRepository.consume(active.id());
            return OttVerificationResult.failure();
        }
        final var attempts = oneTimeCodeRepository.incrementAttempts(active.id());
        if (attempts > ottPolicy.maxAttempts()) {
            oneTimeCodeRepository.consume(active.id());
            return OttVerificationResult.failure();
        }
        if (!oneTimeCodeHasher.matches(code, active.codeHash())) {
            if (ottPolicy.isExhausted(attempts)) {
                oneTimeCodeRepository.consume(active.id());
            }
            return OttVerificationResult.failure();
        }
        return accept(active);
    }

    /**
     * Consumes a correct code; a code consumed by a concurrent request is refused.
     *
     * @param active the stored code.
     * @return success when this request consumed it, failure otherwise.
     */
    private OttVerificationResult accept(final OneTimeCode active) {
        return oneTimeCodeRepository.consume(active.id())
                ? OttVerificationResult.success(active.channel())
                : OttVerificationResult.failure();
    }
}
