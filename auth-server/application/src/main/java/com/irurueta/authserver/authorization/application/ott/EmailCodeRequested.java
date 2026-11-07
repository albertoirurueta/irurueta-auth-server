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

import java.time.Duration;

/**
 * Event published when a one-time code must be e-mailed. It is delivered once the transaction that stored the code
 * commits, outside of it and off the request thread, so the mail server's latency neither holds a database connection
 * nor shows in the response (which would tell an existing account from an unknown one).
 *
 * @param address  the verified e-mail address.
 * @param code     the code in clear text.
 * @param validFor how long the code stays valid, shown to the user.
 */
public record EmailCodeRequested(String address, String code, Duration validFor) {

    /**
     * Validates the event.
     *
     * @throws IllegalArgumentException if a value is missing or blank.
     */
    public EmailCodeRequested {
        if (address == null || address.isBlank() || code == null || code.isBlank() || validFor == null) {
            throw new IllegalArgumentException("address, code and validFor are required");
        }
    }

    /**
     * Describes the event without the address and the code, so neither ever reaches a log.
     *
     * @return the description.
     */
    @Override
    public String toString() {
        return "EmailCodeRequested[validFor=" + validFor + "]";
    }
}
