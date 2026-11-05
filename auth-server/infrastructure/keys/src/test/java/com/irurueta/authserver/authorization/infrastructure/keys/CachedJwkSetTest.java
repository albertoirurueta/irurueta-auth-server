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

package com.irurueta.authserver.authorization.infrastructure.keys;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.jwk.JWKSet;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link CachedJwkSet}.
 */
@ExtendWith(MockitoExtension.class)
class CachedJwkSetTest {

    /** Time to live of the cache. */
    private static final Duration TTL = Duration.ofSeconds(30);

    /** Instant at which the set is first loaded. */
    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    /** Loader of the set. */
    @Mock
    private Supplier<JWKSet> loader;

    /** Clock of the cache. */
    @Mock
    private Clock clock;

    /** Set returned by the loader. */
    private final JWKSet first = new JWKSet();

    /** Cache under test. */
    private CachedJwkSet cache;

    /**
     * Creates the cache.
     */
    @BeforeEach
    void setUp() {
        cache = new CachedJwkSet(loader, TTL, clock);
        when(loader.get()).thenReturn(first);
    }

    /**
     * Verifies that a set younger than the time to live is not loaded again.
     */
    @Test
    void get_whenCalledWithinTtl_loadsOnce() {
        when(clock.instant()).thenReturn(START, START.plusSeconds(1));

        assertSame(cache.get(), cache.get());
        verify(loader, times(1)).get();
    }

    /**
     * Verifies that an expired set is loaded again.
     */
    @Test
    void get_whenTtlHasElapsed_loadsAgain() {
        when(clock.instant()).thenReturn(START, START.plus(TTL));

        cache.get();
        cache.get();

        verify(loader, times(2)).get();
    }

    /**
     * Verifies that a refresh forces the next read to load again.
     */
    @Test
    void refresh_whenCalled_loadsAgainOnNextGet() {
        when(clock.instant()).thenReturn(START, START.plusSeconds(1));

        cache.get();
        cache.refresh();
        cache.get();

        verify(loader, times(2)).get();
    }
}
