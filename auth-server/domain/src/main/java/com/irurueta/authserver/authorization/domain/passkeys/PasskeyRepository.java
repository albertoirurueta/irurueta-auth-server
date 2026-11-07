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
package com.irurueta.authserver.authorization.domain.passkeys;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Port that reads and manages the passkeys users registered. Creating a credential and verifying its signatures belong
 * to the WebAuthn framework, so this port only lists, renames and deletes. It never returns {@code null}.
 */
public interface PasskeyRepository {

    /**
     * Finds the WebAuthn user handle of an account.
     *
     * @param username name of the account, as the user entity of the credential store records it.
     * @return the user handle, or an empty optional when the account has no user entity (never registered a passkey).
     */
    Optional<String> findUserIdByUsername(String username);

    /**
     * Lists the passkeys of a user, oldest first.
     *
     * @param userId WebAuthn user handle of the owner.
     * @return the passkeys, possibly empty.
     */
    List<Passkey> findByUserId(String userId);

    /**
     * Finds one passkey of a user.
     *
     * @param id     credential identifier.
     * @param userId WebAuthn user handle of the owner, so nobody can reach another user's passkey.
     * @return the passkey, or an empty optional when the user has no such passkey.
     */
    Optional<Passkey> findByIdAndUserId(String id, String userId);

    /**
     * Renames a passkey of a user.
     *
     * @param id     credential identifier.
     * @param userId WebAuthn user handle of the owner.
     * @param label  new label.
     * @return {@code true} when a passkey was renamed.
     */
    boolean rename(String id, String userId, String label);

    /**
     * Deletes a passkey of a user.
     *
     * @param id     credential identifier.
     * @param userId WebAuthn user handle of the owner.
     * @return {@code true} when a passkey was deleted.
     */
    boolean delete(String id, String userId);

    /**
     * Tells whether an account has registered at least one passkey, in a single lookup.
     *
     * @param accountId identifier of the account (the {@code users} row), not its WebAuthn user handle.
     * @return {@code true} when the account has at least one passkey.
     */
    boolean existsForAccount(UUID accountId);
}
