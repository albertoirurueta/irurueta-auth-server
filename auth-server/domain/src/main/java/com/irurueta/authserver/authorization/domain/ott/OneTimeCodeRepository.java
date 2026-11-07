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
package com.irurueta.authserver.authorization.domain.ott;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Port that stores the numeric one-time codes. An implementation never returns {@code null}.
 */
public interface OneTimeCodeRepository {

    /**
     * Stores a code, replacing any other active code of the same binding and user name so that only the latest one
     * can be used.
     *
     * @param code the code to store.
     */
    void save(OneTimeCode code);

    /**
     * Finds the code that is still active for a binding and a user.
     *
     * @param bindingId identifier binding the code to the requesting browser session.
     * @param username  user name of the account.
     * @param now       current instant; an expired code is not active.
     * @return the active code, or empty when there is none.
     */
    Optional<OneTimeCode> findActive(String bindingId, String username, Instant now);

    /**
     * Counts a wrong submission, in one atomic step.
     *
     * @param id identifier of the code.
     * @return the number of attempts after the increment, or {@code 0} when the code no longer exists.
     */
    int incrementAttempts(UUID id);

    /**
     * Spends a code, in one atomic step, so that two concurrent requests cannot both use it.
     *
     * @param id identifier of the code.
     * @return {@code true} when the code existed and is now spent.
     */
    boolean consume(UUID id);

    /**
     * Deletes every code that has expired.
     *
     * @param now current instant.
     * @return the number of deleted codes.
     */
    int deleteExpired(Instant now);
}
