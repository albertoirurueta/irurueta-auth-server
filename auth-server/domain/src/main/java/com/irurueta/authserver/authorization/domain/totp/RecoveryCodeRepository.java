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

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Port that stores the recovery codes of each user.
 */
public interface RecoveryCodeRepository {

    /**
     * Replaces every code of a user with a new set, which is what regenerating codes means.
     *
     * @param userId identifier of the user.
     * @param codes  the new codes.
     */
    void replaceAll(UUID userId, List<RecoveryCode> codes);

    /**
     * Lists the codes of a user that have not been spent.
     *
     * @param userId identifier of the user.
     * @return the unused codes, possibly empty.
     */
    List<RecoveryCode> findUnused(UUID userId);

    /**
     * Spends a code, in one atomic step, so that two concurrent requests cannot both use it.
     *
     * @param id  identifier of the code.
     * @param now instant of the use.
     * @return {@code true} when the code was unused and is now spent.
     */
    boolean markUsed(UUID id, Instant now);

    /**
     * Deletes every code of a user.
     *
     * @param userId identifier of the user.
     */
    void deleteByUser(UUID userId);
}
