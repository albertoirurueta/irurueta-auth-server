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
import java.util.Optional;

/**
 * Use case that looks a user account up by username. A plain class (final, so that a constructor that rejects its
 * argument cannot leave a partially initialized subclass behind): the {@code boot} module registers it as a
 * bean.
 */
public final class FindUserAccountUseCase {

    /** Port that provides the user accounts. */
    private final UserAccountRepository userAccountRepository;

    /**
     * Creates the use case.
     *
     * @param userAccountRepository port that provides the user accounts.
     * @throws IllegalArgumentException if the port is null.
     */
    public FindUserAccountUseCase(final UserAccountRepository userAccountRepository) {
        if (userAccountRepository == null) {
            throw new IllegalArgumentException("userAccountRepository must not be null");
        }
        this.userAccountRepository = userAccountRepository;
    }

    /**
     * Finds the account of a user.
     *
     * @param username name the user signs in with.
     * @return the account, or an empty optional when no account has that username.
     */
    public Optional<UserAccount> execute(final String username) {
        return userAccountRepository.findByUsername(username);
    }
}
