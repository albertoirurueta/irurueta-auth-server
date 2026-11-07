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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsInboxEntry;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link SmsOutbox}. */
class SmsOutboxTest {

    /** Test fixture. */
    private static final PhoneNumber TO = new PhoneNumber("+34600111222");

    /** Test fixture. */
    private static final int CAPACITY = 2;

    /** An empty outbox has no messages. */
    @Test
    void messages_whenEmpty_returnsEmptyList() {
        assertTrue(new SmsOutbox(CAPACITY).messages().isEmpty());
    }

    /** The oldest message is evicted beyond the capacity. */
    @Test
    void add_whenCapacityExceeded_evictsOldest() {
        final var outbox = new SmsOutbox(CAPACITY);
        final var first = new SentSms(TO, "one", Instant.EPOCH);
        final var second = new SentSms(TO, "two", Instant.EPOCH);
        final var third = new SentSms(TO, "three", Instant.EPOCH);
        outbox.add(first);
        outbox.add(second);
        outbox.add(third);
        assertEquals(java.util.List.of(second, third), outbox.messages());
    }

    /** The snapshot cannot be modified. */
    @Test
    void messages_whenModified_throwsUnsupportedOperationException() {
        final var outbox = new SmsOutbox(CAPACITY);
        final var snapshot = outbox.messages();
        final var message = new SentSms(TO, "one", Instant.EPOCH);
        assertThrows(UnsupportedOperationException.class, () -> snapshot.add(message));
    }

    /** The inbox view lists the recorded messages, oldest first. */
    @Test
    void entries_whenMessagesAreRecorded_listsThemOldestFirst() {
        final var outbox = new SmsOutbox(CAPACITY);
        outbox.add(new SentSms(TO, "one", Instant.EPOCH));
        outbox.add(new SentSms(TO, "two", Instant.EPOCH));

        final var entries = outbox.entries();

        assertEquals(java.util.List.of("one", "two"), entries.stream().map(SmsInboxEntry::text).toList());
        assertEquals(TO, entries.getFirst().to());
    }

    /** A non-positive capacity is refused. */
    @Test
    void constructor_whenCapacityIsZero_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SmsOutbox(0));
    }
}
