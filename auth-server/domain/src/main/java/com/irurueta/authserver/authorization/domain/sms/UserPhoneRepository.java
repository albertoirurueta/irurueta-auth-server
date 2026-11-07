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
package com.irurueta.authserver.authorization.domain.sms;

import java.util.Optional;
import java.util.UUID;

/**
 * Port that stores the verified phone number of each user. An implementation never returns {@code null}.
 */
public interface UserPhoneRepository {

    /**
     * Finds the verified phone of a user.
     *
     * @param userId identifier of the user.
     * @return the phone, or empty when the user has none.
     */
    Optional<UserPhone> findByUserId(UUID userId);

    /**
     * Finds the verified phone that holds a number.
     *
     * @param phone the number.
     * @return the phone, or empty when no user verified it.
     */
    Optional<UserPhone> findByPhone(PhoneNumber phone);

    /**
     * Stores the verified phone of a user, replacing the one it had.
     *
     * @param phone the verified phone.
     * @return {@code false} when another user already holds the number and nothing was stored.
     */
    boolean save(UserPhone phone);

    /**
     * Removes the verified phone of a user.
     *
     * @param userId identifier of the user.
     */
    void deleteByUserId(UUID userId);
}
