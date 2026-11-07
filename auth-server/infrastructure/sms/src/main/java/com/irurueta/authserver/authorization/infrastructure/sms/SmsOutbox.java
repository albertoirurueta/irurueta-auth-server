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

import com.irurueta.authserver.authorization.domain.sms.SmsInbox;
import com.irurueta.authserver.authorization.domain.sms.SmsInboxEntry;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * Bounded, thread-safe, in-memory record of the messages the {@link LoggingSmsSender} "sent", so the development
 * inbox can show them, which reads it through the domain port {@link SmsInbox}. The oldest message is evicted when the
 * capacity is reached.
 */
public final class SmsOutbox implements SmsInbox {

    /** Messages, oldest first. */
    private final Deque<SentSms> messages = new ArrayDeque<>();

    /** Maximum number of messages kept. */
    private final int capacity;

    /**
     * Creates the outbox.
     *
     * @param capacity maximum number of messages kept.
     * @throws IllegalArgumentException if the capacity is not positive.
     */
    public SmsOutbox(final int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.capacity = capacity;
    }

    /**
     * Records a message, evicting the oldest ones beyond the capacity.
     *
     * @param message the message.
     */
    public synchronized void add(final SentSms message) {
        while (messages.size() >= capacity) {
            messages.removeFirst();
        }
        messages.addLast(message);
    }

    /**
     * Reads the recorded messages.
     *
     * @return an immutable snapshot, oldest first.
     */
    public synchronized List<SentSms> messages() {
        return List.copyOf(messages);
    }

    /**
     * Lists the recorded messages as the inbox port describes them.
     *
     * @return an immutable snapshot, oldest first.
     */
    @Override
    public synchronized List<SmsInboxEntry> entries() {
        return messages.stream()
                .map(message -> new SmsInboxEntry(message.to(), message.text(), message.sentAt()))
                .toList();
    }
}
