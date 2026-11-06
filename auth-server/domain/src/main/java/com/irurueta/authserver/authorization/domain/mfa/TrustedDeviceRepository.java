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
package com.irurueta.authserver.authorization.domain.mfa;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Port that stores the devices users trust.
 */
public interface TrustedDeviceRepository {

    /**
     * Stores a new trusted device.
     *
     * @param device the device to store.
     */
    void store(TrustedDevice device);

    /**
     * Finds a device that is still trusted.
     *
     * @param userId      identifier of the user.
     * @param hashedToken hash of the device token presented by the browser.
     * @param now         current instant, compared against the expiry.
     * @return the device, or an empty optional when there is no such unexpired device.
     */
    Optional<TrustedDevice> findUsable(UUID userId, String hashedToken, Instant now);

    /**
     * Lists the devices of a user that are still trusted.
     *
     * @param userId identifier of the user.
     * @param now    current instant, compared against the expiry.
     * @return the unexpired devices, possibly empty.
     */
    List<TrustedDevice> findByUser(UUID userId, Instant now);

    /**
     * Revokes a device of a user.
     *
     * @param userId identifier of the user, so nobody can revoke another user's device.
     * @param id     identifier of the device.
     * @return {@code true} when a device was revoked.
     */
    boolean revoke(UUID userId, UUID id);

    /**
     * Revokes every device of a user, for example when the second factor they skip is removed.
     *
     * @param userId identifier of the user.
     * @return the number of revoked devices.
     */
    int deleteByUser(UUID userId);

    /**
     * Deletes the devices that expired before an instant.
     *
     * @param now current instant.
     * @return the number of deleted devices.
     */
    int deleteExpired(Instant now);
}
