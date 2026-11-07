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

import java.net.URI;
import java.time.Duration;

/**
 * Event published when a magic link must be e-mailed. Like {@link EmailCodeRequested}, it is delivered after the
 * transaction commits, outside of it and off the request thread.
 *
 * @param address  the verified e-mail address.
 * @param link     the link that opens the confirmation page.
 * @param validFor how long the link stays valid, shown to the user.
 */
public record EmailLinkRequested(String address, URI link, Duration validFor) {

    /**
     * Validates the event.
     *
     * @throws IllegalArgumentException if a value is missing or the address is blank.
     */
    public EmailLinkRequested {
        if (address == null || address.isBlank() || link == null || validFor == null) {
            throw new IllegalArgumentException("address, link and validFor are required");
        }
    }

    /**
     * Describes the event without the address and the link, so neither ever reaches a log.
     *
     * @return the description.
     */
    @Override
    public String toString() {
        return "EmailLinkRequested[validFor=" + validFor + "]";
    }
}
