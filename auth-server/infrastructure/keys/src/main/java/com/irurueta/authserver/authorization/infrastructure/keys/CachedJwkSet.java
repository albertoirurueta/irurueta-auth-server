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

import com.nimbusds.jose.jwk.JWKSet;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

/**
 * A JSON Web Key set loaded lazily and kept in memory for a short time, so that verifying or signing a token does not
 * read the database every time. A rotation calls {@link #refresh()} so the next read sees the new keys at once;
 * otherwise the set is reloaded when it is older than the time to live.
 */
public class CachedJwkSet {

    /** Loads the set. */
    private final Supplier<JWKSet> loader;

    /** How long a loaded set is kept. */
    private final Duration ttl;

    /** Source of the current time. */
    private final Clock clock;

    /** The cached set, or {@code null} when none is loaded. */
    private JWKSet cached;

    /** Instant at which the cached set was loaded. */
    private Instant loadedAt;

    /**
     * Creates an empty cache.
     *
     * @param loader loads the set.
     * @param ttl    how long a loaded set is kept.
     * @param clock  source of the current time.
     */
    public CachedJwkSet(final Supplier<JWKSet> loader, final Duration ttl, final Clock clock) {
        this.loader = loader;
        this.ttl = ttl;
        this.clock = clock;
    }

    /**
     * Gets the set, loading it when none is cached or the cached one has expired.
     *
     * @return the set.
     */
    public synchronized JWKSet get() {
        final var now = clock.instant();
        if (cached == null || !loadedAt.plus(ttl).isAfter(now)) {
            cached = loader.get();
            loadedAt = now;
        }
        return cached;
    }

    /**
     * Drops the cached set, so the next read loads it again. Called after the keys rotate.
     */
    public synchronized void refresh() {
        cached = null;
    }
}
