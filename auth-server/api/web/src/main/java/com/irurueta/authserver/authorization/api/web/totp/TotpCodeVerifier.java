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

import com.irurueta.authserver.authorization.application.totp.ConfirmTotpAtSignInUseCase;
import com.irurueta.authserver.authorization.application.totp.VerifyRecoveryCodeUseCase;
import com.irurueta.authserver.authorization.application.totp.VerifyTotpUseCase;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Sends a posted code to the use case of its kind ({@link TotpCodeKind}): a TOTP code, a recovery code, or the first
 * code of an authenticator app enrolled during the sign-in. The use cases count the failures, lock the second factor
 * after too many and clear the counter on success.
 */
@Component
@RequiredArgsConstructor
public class TotpCodeVerifier {

    /** Use case that verifies a TOTP code. */
    private final VerifyTotpUseCase verifyTotpUseCase;

    /** Use case that verifies (and consumes) a recovery code. */
    private final VerifyRecoveryCodeUseCase verifyRecoveryCodeUseCase;

    /** Use case that confirms an enrolment during the sign-in. */
    private final ConfirmTotpAtSignInUseCase confirmTotpAtSignInUseCase;

    /**
     * Verifies a posted code; for an enrolment, the new recovery codes are handed back through the request.
     *
     * @param request  the verification request.
     * @param userId   identifier of the user.
     * @param username name of the user, for the audit log.
     * @return {@code true} when the code is accepted.
     * @throws com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockedException if the second factor of
     *         the user is locked.
     * @throws com.irurueta.authserver.authorization.domain.totp.TotpNotEnrolledException if an enrolment code is
     *         posted while no enrolment was started.
     * @throws com.irurueta.authserver.authorization.domain.totp.TotpAlreadyEnabledException if an enrolment code is
     *         posted for an app that is already enabled.
     */
    public boolean verify(final TotpAuthenticationToken request, final UUID userId, final String username) {
        return switch (request.kind()) {
            case TOTP -> verifyTotpUseCase.execute(userId, username, request.getCredentials());
            case RECOVERY -> verifyRecoveryCodeUseCase.execute(userId, username, request.getCredentials());
            case ENROLMENT -> confirmEnrolment(request, userId, username);
        };
    }

    /**
     * Confirms an enrolment and hands the new recovery codes back through the request.
     *
     * @param request  the verification request.
     * @param userId   identifier of the user.
     * @param username name of the user.
     * @return {@code true} when the code confirmed the enrolment.
     */
    private boolean confirmEnrolment(final TotpAuthenticationToken request, final UUID userId,
            final String username) {
        final var recoveryCodes = confirmTotpAtSignInUseCase.execute(userId, username, request.getCredentials());
        recoveryCodes.ifPresent(request::issueRecoveryCodes);
        return recoveryCodes.isPresent();
    }
}
