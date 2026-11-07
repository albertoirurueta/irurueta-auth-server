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

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings of the {@link SmsOutbox}.
 *
 * @param capacity maximum number of messages kept; the oldest is evicted first.
 */
@ConfigurationProperties(prefix = "authserver.sms.outbox")
public record SmsOutboxProperties(int capacity) {

    /** Capacity used when none is configured. */
    public static final int DEFAULT_CAPACITY = 100;

    /**
     * Applies the default capacity when the configured one is not positive.
     *
     * @param capacity maximum number of messages kept, or zero for {@link #DEFAULT_CAPACITY}.
     */
    public SmsOutboxProperties {
        capacity = capacity <= 0 ? DEFAULT_CAPACITY : capacity;
    }
}
