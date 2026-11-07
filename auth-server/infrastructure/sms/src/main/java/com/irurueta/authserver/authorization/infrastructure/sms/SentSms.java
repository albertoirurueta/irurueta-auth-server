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

package com.irurueta.authserver.authorization.infrastructure.sms;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import java.time.Instant;

/**
 * A text message recorded by the {@link SmsOutbox}. It holds the text, so it is meant for the development inbox only
 * and is never logged.
 *
 * @param to     recipient.
 * @param text   text of the message.
 * @param sentAt instant the message was recorded.
 */
public record SentSms(PhoneNumber to, String text, Instant sentAt) {

    /**
     * Validates the record.
     *
     * @throws IllegalArgumentException if any component is missing.
     */
    public SentSms {
        if (to == null || text == null || sentAt == null) {
            throw new IllegalArgumentException("to, text and sentAt must not be null");
        }
    }

    @Override
    public String toString() {
        return "SentSms[to=" + to.e164() + ", sentAt=" + sentAt + "]";
    }
}
