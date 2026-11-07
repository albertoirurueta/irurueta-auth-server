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

import java.time.Instant;

/**
 * A text message a development sender recorded instead of sending it, as the development inbox shows it.
 *
 * @param to     recipient.
 * @param text   text of the message.
 * @param sentAt when the sender recorded it.
 */
public record SmsInboxEntry(PhoneNumber to, String text, Instant sentAt) {

    /**
     * Validates the entry.
     *
     * @throws IllegalArgumentException if any component is {@code null}.
     */
    public SmsInboxEntry {
        if (to == null || text == null || sentAt == null) {
            throw new IllegalArgumentException("to, text and sentAt must not be null");
        }
    }

    /**
     * Describes the entry without the text, which carries a one-time code.
     *
     * @return the recipient and the time only.
     */
    @Override
    public String toString() {
        return "SmsInboxEntry[to=" + to.e164() + ", sentAt=" + sentAt + "]";
    }
}
