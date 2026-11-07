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

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link LoggingSmsSender}. */
class LoggingSmsSenderTest {

    /** Test fixture. */
    private static final PhoneNumber TO = new PhoneNumber("+34600111222");

    /** Test fixture. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** The message lands in the outbox with the clock's instant. */
    @Test
    void send_whenCalled_recordsMessageInOutbox() {
        final var outbox = new SmsOutbox(SmsOutboxProperties.DEFAULT_CAPACITY);
        final var sender = new LoggingSmsSender(outbox, Clock.fixed(NOW, ZoneOffset.UTC));

        sender.send(TO, "code 123456");

        assertEquals(java.util.List.of(new SentSms(TO, "code 123456", NOW)), outbox.messages());
    }

    /** The outbox stays bounded. */
    @Test
    void send_whenOutboxIsFull_evictsOldest() {
        final var outbox = new SmsOutbox(1);
        final var sender = new LoggingSmsSender(outbox, Clock.fixed(NOW, ZoneOffset.UTC));

        sender.send(TO, "first");
        sender.send(TO, "second");

        assertEquals(java.util.List.of(new SentSms(TO, "second", NOW)), outbox.messages());
    }
}
