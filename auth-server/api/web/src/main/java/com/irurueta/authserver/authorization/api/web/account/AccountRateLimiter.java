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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.TimeMeter;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

// tag::account-rate-limit[]
/**
 * Rate limiter of the unauthenticated account endpoints (register, verify, reset request, reset), built on
 * <a href="https://bucket4j.com">Bucket4j</a> token buckets. Requests are limited twice: per client address, and
 * per e-mail address when the request names one, so neither a single client nor many clients aiming at one
 * address can flood the server (and the mailboxes) with account mail or guess reset tokens. Each bucket holds the
 * limit of its key and is refilled all at once every {@link AccountRateLimitProperties#window()}.
 *
 * <p>The buckets of each kind of key live in a Caffeine cache bounded to
 * {@link AccountRateLimitProperties#maxTrackedKeys()} entries, which also drops a bucket idle for a whole window
 * (it would be full again anyway). They live in this instance only: several instances each apply the limits on
 * their own, until the buckets move to a shared store through a Bucket4j {@code ProxyManager} (for example
 * {@code bucket4j-postgresql}). The client address is {@code request.getRemoteAddr()}, so behind a proxy
 * {@code server.forward-headers-strategy} must be set for it to be the real client.
 */
@Component
@EnableConfigurationProperties(AccountRateLimitProperties.class)
public final class AccountRateLimiter {

    /** Limits, window and bound of the tracked keys. */
    private final AccountRateLimitProperties properties;

    /** Time source of the buckets and of the caches, read from the injected clock so tests can move it. */
    private final ClockTimeMeter timeMeter;

    /** Buckets per client address. */
    private final Cache<String, Bucket> clients;

    /** Buckets per (lower-cased) e-mail address. */
    private final Cache<String, Bucket> emails;

    /**
     * Creates the limiter.
     *
     * @param properties limits, window and bound of the tracked keys.
     * @param clock      source of the current time.
     */
    public AccountRateLimiter(final AccountRateLimitProperties properties, final Clock clock) {
        this.properties = properties;
        timeMeter = new ClockTimeMeter(clock);
        clients = cache();
        emails = cache();
    }

    /**
     * Counts one request and rejects it once a limit is exceeded.
     *
     * @param clientAddress address of the calling client.
     * @param email         e-mail address the request names, or {@code null}.
     * @throws AccountRateLimitExceededException if the client or the e-mail address exceeded its limit.
     */
    public void check(final String clientAddress, final String email) {
        if (!properties.enabled()) {
            return;
        }
        consume(clients, clientAddress, properties.perClient());
        if (email != null) {
            consume(emails, email.toLowerCase(Locale.ROOT), properties.perEmail());
        }
    }

    /**
     * Tells how many keys of each kind are tracked, after any pending eviction.
     *
     * @return the number of client keys plus the number of e-mail keys.
     */
    long trackedKeys() {
        clients.cleanUp();
        emails.cleanUp();
        return clients.estimatedSize() + emails.estimatedSize();
    }

    /**
     * Takes one token from the bucket of a key, creating the bucket on first use.
     *
     * @param buckets buckets of one kind of key.
     * @param key     the key.
     * @param limit   requests the key may make per window.
     * @throws AccountRateLimitExceededException if the bucket is empty.
     */
    private void consume(final Cache<String, Bucket> buckets, final String key, final int limit) {
        final var probe = buckets.get(key, ignored -> bucket(limit)).tryConsumeAndReturnRemaining(1);
        if (!probe.isConsumed()) {
            throw new AccountRateLimitExceededException(Duration.ofNanos(probe.getNanosToWaitForRefill()));
        }
    }

    /**
     * Builds the bucket of a key: the whole limit, refilled at once at the end of every window.
     *
     * @param limit requests per window.
     * @return the bucket.
     */
    private Bucket bucket(final int limit) {
        return Bucket.builder()
                .addLimit(bandwidth -> bandwidth.capacity(limit).refillIntervally(limit, properties.window()))
                .withCustomTimePrecision(timeMeter)
                .build();
    }

    /**
     * Builds the cache of the buckets of one kind of key. Maintenance runs on the calling thread, so eviction is
     * deterministic and needs no extra thread.
     *
     * @return the cache.
     */
    private Cache<String, Bucket> cache() {
        return Caffeine.newBuilder()
                .maximumSize(properties.maxTrackedKeys())
                .expireAfterAccess(properties.window())
                .ticker(timeMeter::currentTimeNanos)
                .executor(Runnable::run)
                .build();
    }

    /**
     * Bucket4j and Caffeine time source backed by a {@link Clock}.
     *
     * @param clock source of the current time.
     */
    private record ClockTimeMeter(Clock clock) implements TimeMeter {

        @Override
        public long currentTimeNanos() {
            return ChronoUnit.NANOS.between(Instant.EPOCH, clock.instant());
        }

        @Override
        public boolean isWallClockBased() {
            return true;
        }
    }
}
// end::account-rate-limit[]
