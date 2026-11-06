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
package com.irurueta.authserver.authorization.domain.totp;

import java.util.Optional;
import java.util.UUID;

/**
 * Port that stores the TOTP credential of each user.
 */
public interface TotpCredentialRepository {

    /**
     * Finds the credential of a user.
     *
     * @param userId identifier of the user.
     * @return the credential, or an empty optional when the user has none.
     */
    Optional<TotpCredential> findByUser(UUID userId);

    /**
     * Stores a credential, replacing any previous one of the same user.
     *
     * @param credential the credential to store.
     */
    void save(TotpCredential credential);

    /**
     * Marks the credential of a user as confirmed.
     *
     * @param userId identifier of the user.
     */
    void confirm(UUID userId);

    /**
     * Records the step of an accepted code, in one atomic step that only succeeds when the step is newer than the
     * stored one, so that two concurrent requests cannot both spend the same code.
     *
     * @param userId identifier of the user.
     * @param step   step of the accepted code.
     * @return {@code true} when the step was newer and has been recorded.
     */
    boolean advanceLastUsedStep(UUID userId, long step);

    /**
     * Deletes the credential of a user.
     *
     * @param userId identifier of the user.
     */
    void deleteByUser(UUID userId);
}
