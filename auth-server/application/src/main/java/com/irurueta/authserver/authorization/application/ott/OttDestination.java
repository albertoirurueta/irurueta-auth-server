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

package com.irurueta.authserver.authorization.application.ott;

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import java.util.UUID;

/**
 * Where a one-time code of a user is delivered.
 *
 * @param userId  identifier of the user.
 * @param channel the channel.
 * @param address the e-mail address or the E.164 phone number.
 */
public record OttDestination(UUID userId, OttChannel channel, String address) {

    /**
     * Validates the destination.
     *
     * @throws IllegalArgumentException if a component is missing or the address is blank.
     */
    public OttDestination {
        if (userId == null || channel == null || address == null || address.isBlank()) {
            throw new IllegalArgumentException("userId, channel and address are required");
        }
    }

    /**
     * Describes the destination without the address, so it never reaches a log.
     *
     * @return the description.
     */
    @Override
    public String toString() {
        return "OttDestination[userId=" + userId + ", channel=" + channel + "]";
    }
}
