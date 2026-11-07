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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** Unit tests of {@link FixedWindowBuckets}, with a mocked clock. */
@ExtendWith(MockitoExtension.class)
class FixedWindowBucketsTest {

    /** Start of the first window. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Length of a window. */
    private static final Duration WINDOW = Duration.ofMinutes(15);

    /** Requests a key may make in a window. */
    private static final int LIMIT = 2;

    /** Keys tracked at most. */
    private static final int MAX_KEYS = 2;

    /** Seconds into the window of the request that is rejected. */
    private static final long LATE_SECONDS = 60;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Requests within the limit are accepted; the next one is told how long to wait. */
    @Test
    void tryConsume_whenTheLimitIsExceeded_returnsTheRestOfTheWindow() {
        final var buckets = new FixedWindowBuckets(clock, WINDOW, MAX_KEYS);
        when(clock.instant()).thenReturn(NOW);
        assertTrue(buckets.tryConsume("a", LIMIT).isEmpty());
        assertTrue(buckets.tryConsume("a", LIMIT).isEmpty());
        when(clock.instant()).thenReturn(NOW.plusSeconds(LATE_SECONDS));

        assertEquals(WINDOW.minusSeconds(LATE_SECONDS), buckets.tryConsume("a", LIMIT).orElseThrow());
        assertTrue(buckets.tryConsume("b", LIMIT).isEmpty(), "other keys are counted apart");
    }

    /** A new window starts once the previous one has elapsed. */
    @Test
    void tryConsume_whenTheWindowHasElapsed_acceptsAgain() {
        final var buckets = new FixedWindowBuckets(clock, WINDOW, MAX_KEYS);
        when(clock.instant()).thenReturn(NOW);
        buckets.tryConsume("a", LIMIT);
        buckets.tryConsume("a", LIMIT);
        when(clock.instant()).thenReturn(NOW.plus(WINDOW));

        assertTrue(buckets.tryConsume("a", LIMIT).isEmpty());
    }

    /** The tracked keys stay within their bound. */
    @Test
    void trackedKeys_whenMoreKeysThanTheBound_staysBounded() {
        final var buckets = new FixedWindowBuckets(clock, WINDOW, MAX_KEYS);
        when(clock.instant()).thenReturn(NOW);
        buckets.tryConsume("a", LIMIT);
        buckets.tryConsume("b", LIMIT);
        buckets.tryConsume("c", LIMIT);

        assertEquals(MAX_KEYS, buckets.trackedKeys());
    }
}
