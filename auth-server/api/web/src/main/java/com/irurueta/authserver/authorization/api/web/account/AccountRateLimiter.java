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

package com.irurueta.authserver.authorization.api.web.account;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

// tag::account-rate-limit[]
/**
 * In-memory, bounded rate limiter of the unauthenticated account endpoints (register, verify, reset request, reset).
 * Requests are counted in fixed windows twice: per client address, and per e-mail address when the request names
 * one, so neither a single client nor many clients aiming at one address can flood the server (and the mailboxes)
 * with account mail or guess reset tokens. Each kind of key keeps at most
 * {@link AccountRateLimitProperties#maxTrackedKeys()} counters, forgetting the oldest first.
 *
 * <p>The counters live in this instance only: several instances each apply the limits on their own. The client
 * address is {@code request.getRemoteAddr()}, so behind a proxy {@code server.forward-headers-strategy} must be set
 * for it to be the real client.
 */
@Component
@EnableConfigurationProperties(AccountRateLimitProperties.class)
public class AccountRateLimiter {

    /** Configuration of the limits. */
    private final AccountRateLimitProperties properties;

    /** Source of the current time. */
    private final Clock clock;

    /** Counters per client address. */
    private final Counters clients;

    /** Counters per e-mail address. */
    private final Counters emails;

    /**
     * Creates the limiter and its bounded counters.
     *
     * @param properties configuration of the limits.
     * @param clock      source of the current time.
     */
    public AccountRateLimiter(final AccountRateLimitProperties properties, final Clock clock) {
        this.properties = properties;
        this.clock = clock;
        clients = new Counters(properties.window(), properties.maxTrackedKeys());
        emails = new Counters(properties.window(), properties.maxTrackedKeys());
    }

    /**
     * Counts one request and rejects it when its client address or its e-mail address is over the limit.
     *
     * @param clientAddress address of the client.
     * @param email         e-mail address the request names, or {@code null} when it names none.
     * @throws AccountRateLimitExceededException if a limit is exceeded.
     */
    public void check(final String clientAddress, final String email) {
        if (!properties.enabled()) {
            return;
        }
        final var now = clock.instant();
        clients.acquire(clientAddress, properties.perClient(), now);
        if (email != null) {
            emails.acquire(email.toLowerCase(Locale.ROOT), properties.perEmail(), now);
        }
    }

    /**
     * Fixed-window counters, bounded in number.
     */
    private static final class Counters {

        /** Length of a window. */
        private final Duration window;

        /** Number of keys tracked at most. */
        private final int maxKeys;

        /** Window of each key, oldest first. */
        private final Map<String, Window> windows = new LinkedHashMap<>();

        /**
         * Creates empty counters.
         *
         * @param window  length of a window.
         * @param maxKeys number of keys tracked at most.
         */
        private Counters(final Duration window, final int maxKeys) {
            this.window = window;
            this.maxKeys = maxKeys;
        }

        /**
         * Counts a request of a key.
         *
         * @param key   the key.
         * @param limit requests the key may make in a window.
         * @param now   current instant.
         * @throws AccountRateLimitExceededException if the key is over the limit.
         */
        private synchronized void acquire(final String key, final int limit, final Instant now) {
            var current = windows.remove(key);
            if (current == null || !current.start().plus(window).isAfter(now)) {
                current = new Window(now, 0);
            }
            if (windows.size() >= maxKeys) {
                final var eldest = windows.keySet().iterator();
                eldest.next();
                eldest.remove();
            }
            final var counted = new Window(current.start(), current.count() + 1);
            windows.put(key, counted);
            if (counted.count() > limit) {
                throw new AccountRateLimitExceededException(Duration.between(now, counted.start().plus(window)));
            }
        }
    }

    /**
     * The requests of one key in its current window.
     *
     * @param start instant the window started.
     * @param count requests counted in the window.
     */
    private record Window(Instant start, int count) {
    }
}
// end::account-rate-limit[]
