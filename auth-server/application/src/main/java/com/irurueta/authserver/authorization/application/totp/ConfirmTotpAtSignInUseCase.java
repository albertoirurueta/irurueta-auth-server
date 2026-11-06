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

import com.irurueta.authserver.authorization.application.mfa.CheckSecondFactorLockoutUseCase;
import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.application.mfa.RegisterSecondFactorFailureUseCase;
import com.irurueta.authserver.authorization.application.mfa.ResetSecondFactorFailuresUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockedException;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that confirms the enrolment of an authenticator app inside the sign-in, where the code also stands as the
 * second factor of that sign-in: like {@link VerifyTotpUseCase}, a locked second factor is refused, a wrong code
 * counts towards the lockout and a right one clears the counter and is audited.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class ConfirmTotpAtSignInUseCase {

    /** Use case that confirms the enrolment. */
    private final ConfirmTotpUseCase confirmTotpUseCase;

    /** Use case that tells whether the second factor is locked (and serializes the attempts of a user). */
    private final CheckSecondFactorLockoutUseCase checkSecondFactorLockoutUseCase;

    /** Use case that counts a failure. */
    private final RegisterSecondFactorFailureUseCase registerSecondFactorFailureUseCase;

    /** Use case that clears the failures. */
    private final ResetSecondFactorFailuresUseCase resetSecondFactorFailuresUseCase;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    // tag::totp-sign-in-enrolment[]
    /**
     * Confirms the enrolment with the first code of the authenticator app.
     *
     * @param userId   identifier of the user.
     * @param username name of the user, for the audit log.
     * @param code     the code as typed.
     * @return the clear-text recovery codes, to be shown once; empty when the code is wrong (the failure is counted).
     * @throws SecondFactorLockedException if the second factor of the user is locked.
     * @throws com.irurueta.authserver.authorization.domain.totp.TotpNotEnrolledException    if no enrolment was
     *                                                                                      started.
     * @throws com.irurueta.authserver.authorization.domain.totp.TotpAlreadyEnabledException if the enrolment was
     *                                                                                      already confirmed.
     */
    public Optional<List<String>> execute(final UUID userId, final String username, final String code) {
        if (checkSecondFactorLockoutUseCase.execute(userId)) {
            throw new SecondFactorLockedException("The second factor is locked after too many failed attempts");
        }
        final var recoveryCodes = confirmTotpUseCase.tryConfirm(userId, code);
        if (recoveryCodes.isPresent()) {
            resetSecondFactorFailuresUseCase.execute(userId);
            recordSecurityEventUseCase.execute(SecurityEventType.SECOND_FACTOR_SUCCESS, userId, username,
                    "totp enrolment");
        } else {
            registerSecondFactorFailureUseCase.execute(userId, username);
        }
        return recoveryCodes;
    }
    // end::totp-sign-in-enrolment[]
}
