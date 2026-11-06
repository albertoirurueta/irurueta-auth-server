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

package com.irurueta.authserver.authorization.application.mfa;

import com.irurueta.authserver.authorization.domain.mfa.UserMfaSettingsRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that tells whether the account of a user requires a second factor, whatever the client being served.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class IsUserMfaRequiredUseCase {

    /** Port that provides the user accounts. */
    private final UserAccountRepository userAccountRepository;

    /** Port that stores the per-user multi-factor settings. */
    private final UserMfaSettingsRepository userMfaSettingsRepository;

    /**
     * Tells whether an account requires a second factor.
     *
     * @param username name the user signs in with.
     * @return {@code true} when the account exists and requires it; {@code false} when it does not or does not exist.
     */
    public boolean execute(final String username) {
        return userAccountRepository.findByUsername(username)
                .map(UserAccount::id)
                .map(userMfaSettingsRepository::isRequired)
                .orElse(false);
    }
}
