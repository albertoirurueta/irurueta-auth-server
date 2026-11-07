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
package com.irurueta.authserver.authorization.application.sms;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;

/**
 * Event published when a text message, whose cost is already recorded within the budget, must be sent. It is sent once
 * the transaction that recorded it commits, outside of it and off the request thread, so the gateway's latency neither
 * holds a database connection nor shows in the response.
 *
 * @param to   the destination.
 * @param text the text, which may carry a code.
 */
public record SmsRequested(PhoneNumber to, String text) {

    /**
     * Validates the event.
     *
     * @throws IllegalArgumentException if a value is missing or the text is blank.
     */
    public SmsRequested {
        if (to == null || text == null || text.isBlank()) {
            throw new IllegalArgumentException("to and text are required");
        }
    }

    /**
     * Describes the event without the number and the text, so neither ever reaches a log.
     *
     * @return the description.
     */
    @Override
    public String toString() {
        return "SmsRequested[]";
    }
}
