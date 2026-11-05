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

package com.irurueta.authserver.authorization.application.password;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Use case that replaces the stored password hash of a user with one made by the current algorithm, right after a
 * successful sign-in (the only moment the clear-text password is known). The authentication framework decides that
 * the stored encoding is outdated and re-encodes the verified password itself; this use case only stores the result.
 */
@Service
@RequiredArgsConstructor
public class UpgradePasswordHashUseCase {

    /** Port that stores the accounts. */
    private final UserAccountRepository userAccountRepository;

    // tag::password-upgrade[]
    /**
     * Stores a password hash that was already produced by the current algorithm, as the authentication framework
     * does after a sign-in (it re-encodes the verified clear-text password itself).
     *
     * @param account         the account that just signed in.
     * @param encodedPassword the new encoded password.
     */
    public void replaceHash(final UserAccount account, final String encodedPassword) {
        userAccountRepository.updatePassword(account.id(), encodedPassword);
    }
    // end::password-upgrade[]
}
