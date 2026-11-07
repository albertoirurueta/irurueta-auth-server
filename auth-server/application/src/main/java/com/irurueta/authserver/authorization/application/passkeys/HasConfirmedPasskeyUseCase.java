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

import com.irurueta.authserver.authorization.application.mfa.SecondFactorEnrolmentQuery;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that tells whether a user has registered a passkey. It is also the passkey
 * {@link SecondFactorEnrolmentQuery}: a passkey is registered only by a signed-in user and verified by the browser
 * before it is stored, so a registered passkey is always confirmed, and it makes the second factor required.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class HasConfirmedPasskeyUseCase implements SecondFactorEnrolmentQuery {

    /** Port that reads the passkeys. */
    private final PasskeyRepository passkeyRepository;

    /** Port that resolves the account name of a user identifier. */
    private final UserAccountRepository userAccountRepository;

    /**
     * Tells whether a user has at least one passkey.
     *
     * @param userId identifier of the user.
     * @return {@code true} when the user has registered a passkey.
     */
    public boolean execute(final UUID userId) {
        return userAccountRepository.findById(userId)
                .flatMap(account -> passkeyRepository.findUserIdByUsername(account.username()))
                .map(handle -> passkeyRepository.countByUserId(handle) > 0)
                .orElse(false);
    }

    /**
     * Tells whether a user has confirmed the passkey second factor.
     *
     * @param userId identifier of the user.
     * @return the same as {@link #execute(UUID)}.
     */
    @Override
    public boolean hasConfirmed(final UUID userId) {
        return execute(userId);
    }
}
