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

package com.irurueta.authserver.authorization.application.passkeys;

import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyNotFoundException;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that deletes a passkey of a user and audits the removal. When that leaves the user without any confirmed
 * second factor, every trusted device of the user is revoked too, as disabling TOTP does: a remembered browser stands
 * in for a second factor the user no longer has.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class DeletePasskeyUseCase {

    /** Port that stores the passkeys. */
    private final PasskeyRepository passkeyRepository;

    /** Use case telling whether the user still has a confirmed second factor. */
    private final HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Port that stores the trusted devices. */
    private final TrustedDeviceRepository trustedDeviceRepository;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /**
     * Deletes a passkey; a passkey of another account is never touched.
     *
     * @param userId   identifier of the signed-in user, for the audit log.
     * @param username name of the signed-in account.
     * @param id       credential identifier.
     * @throws PasskeyNotFoundException if the account has no passkey with that identifier.
     */
    public void execute(final UUID userId, final String username, final String id) {
        final var ownerId = passkeyRepository.findUserIdByUsername(username)
                .orElseThrow(() -> new PasskeyNotFoundException("The account has no passkeys"));
        if (!passkeyRepository.delete(id, ownerId)) {
            throw new PasskeyNotFoundException("The account has no passkey " + id);
        }
        var detail = "passkey";
        if (!hasConfirmedSecondFactorUseCase.execute(userId)) {
            final var revoked = trustedDeviceRepository.deleteByUser(userId);
            detail = detail + "; trusted devices revoked: " + revoked;
        }
        recordSecurityEventUseCase.execute(SecurityEventType.SECOND_FACTOR_REMOVED, userId, username, detail);
    }
}
