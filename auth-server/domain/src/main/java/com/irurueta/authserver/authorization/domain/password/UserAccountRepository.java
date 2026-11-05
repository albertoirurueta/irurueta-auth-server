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

package com.irurueta.authserver.authorization.domain.password;

import java.util.Optional;
import java.util.UUID;

/**
 * Port that provides the user accounts able to sign in with a password. An implementation never returns
 * {@code null} and never lets a framework or storage type escape through it.
 */
public interface UserAccountRepository {

    /**
     * Finds a user account by the name the user signs in with.
     *
     * @param username name the user signs in with.
     * @return the account, or an empty optional when no account has that username.
     */
    Optional<UserAccount> findByUsername(String username);

    /**
     * Finds a user account by its identifier.
     *
     * @param id identifier of the account.
     * @return the account, or an empty optional when there is none.
     */
    Optional<UserAccount> findById(UUID id);

    /**
     * Finds a user account by its e-mail address.
     *
     * @param email e-mail address of the user.
     * @return the account, or an empty optional when no account has that address.
     */
    Optional<UserAccount> findByEmail(String email);

    /**
     * Tells whether an account with a username exists.
     *
     * @param username name the user signs in with.
     * @return {@code true} when an account has that username.
     */
    boolean existsByUsername(String username);

    /**
     * Stores a new account, with its authorities.
     *
     * @param account the account to create.
     */
    void save(UserAccount account);

    /**
     * Replaces the encoded password of an account.
     *
     * @param userId          identifier of the account.
     * @param encodedPassword the new encoded password.
     */
    void updatePassword(UUID userId, String encodedPassword);

    /**
     * Marks the e-mail address of an account as verified and enables the account.
     *
     * @param userId identifier of the account.
     */
    void markEmailVerified(UUID userId);
}
