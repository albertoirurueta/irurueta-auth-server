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

import com.irurueta.authserver.authorization.domain.passkeys.InvalidPasskeyLabelException;
import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyNotFoundException;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * Use case that renames a passkey of a user.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class RenamePasskeyUseCase {

    /** Longest label accepted, in characters. */
    public static final int MAX_LABEL_LENGTH = 100;

    /** Port that stores the passkeys. */
    private final PasskeyRepository passkeyRepository;

    /**
     * Renames a passkey; a passkey of another account is never touched.
     *
     * @param username name of the signed-in account.
     * @param id       credential identifier.
     * @param label    new label; it is trimmed.
     * @return the renamed passkey.
     * @throws InvalidPasskeyLabelException if the label is blank or longer than {@link #MAX_LABEL_LENGTH} once trimmed.
     * @throws PasskeyNotFoundException if the account has no passkey with that identifier.
     */
    public Passkey execute(final String username, final String id, final String label) {
        if (!StringUtils.hasText(label)) {
            throw new InvalidPasskeyLabelException("label must not be blank");
        }
        final var trimmed = label.trim();
        if (trimmed.length() > MAX_LABEL_LENGTH) {
            throw new InvalidPasskeyLabelException("label must have at most " + MAX_LABEL_LENGTH + " characters");
        }
        final var userId = passkeyRepository.findUserIdByUsername(username)
                .orElseThrow(() -> new PasskeyNotFoundException("The account has no passkeys"));
        if (!passkeyRepository.rename(id, userId, trimmed)) {
            throw new PasskeyNotFoundException("The account has no passkey " + id);
        }
        return passkeyRepository.findByIdAndUserId(id, userId)
                .orElseThrow(() -> new PasskeyNotFoundException("The account has no passkey " + id));
    }
}
