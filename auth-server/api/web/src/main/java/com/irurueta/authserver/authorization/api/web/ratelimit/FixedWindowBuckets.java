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
package com.irurueta.authserver.authorization.api.web.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.TimeMeter;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

/**
 * The token buckets of one kind of key (a client address, an e-mail address, an identifier), built on
 * <a href="https://bucket4j.com">Bucket4j</a> and kept in a Caffeine cache. Each bucket holds the limit of its key and
 * is refilled all at once at the end of every window. The cache is bounded to a number of keys and drops a bucket idle
 * for a whole window (it would be full again anyway). Maintenance runs on the calling thread, so eviction is
 * deterministic and needs no extra thread, and the time of both libraries is read from the injected {@link Clock}, so
 * tests can move it. The buckets live in this instance only: several instances each apply the limits on their own.
 */
public final class FixedWindowBuckets {

    /** Length of the window a limit is counted in. */
    private final Duration window;

    /** Time source of the buckets and of the cache. */
    private final ClockTimeMeter timeMeter;

    /** Buckets per key. */
    private final Cache<String, Bucket> buckets;

    /**
     * Creates the buckets of one kind of key.
     *
     * @param clock          source of the current time.
     * @param window         length of the window a limit is counted in.
     * @param maxTrackedKeys keys tracked at most; the oldest is forgotten first.
     */
    public FixedWindowBuckets(final Clock clock, final Duration window, final int maxTrackedKeys) {
        this.window = window;
        timeMeter = new ClockTimeMeter(clock);
        buckets = Caffeine.newBuilder()
                .maximumSize(maxTrackedKeys)
                .expireAfterAccess(window)
                .ticker(timeMeter::currentTimeNanos)
                .executor(Runnable::run)
                .build();
    }

    /**
     * Takes one token from the bucket of a key, creating the bucket on first use.
     *
     * @param key   the key.
     * @param limit requests the key may make per window.
     * @return empty when the request is within the limit, else how long until the window ends and the key is
     *         accepted again.
     */
    public Optional<Duration> tryConsume(final String key, final int limit) {
        final var probe = buckets.get(key, ignored -> bucket(limit)).tryConsumeAndReturnRemaining(1);
        return probe.isConsumed() ? Optional.empty() : Optional.of(Duration.ofNanos(probe.getNanosToWaitForRefill()));
    }

    /**
     * Tells how many keys are tracked, after any pending eviction.
     *
     * @return the number of keys.
     */
    public long trackedKeys() {
        buckets.cleanUp();
        return buckets.estimatedSize();
    }

    /**
     * Builds the bucket of a key: the whole limit, refilled at once at the end of every window.
     *
     * @param limit requests per window.
     * @return the bucket.
     */
    private Bucket bucket(final int limit) {
        return Bucket.builder()
                .addLimit(bandwidth -> bandwidth.capacity(limit).refillIntervally(limit, window))
                .withCustomTimePrecision(timeMeter)
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
