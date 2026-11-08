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

package com.irurueta.authserver.authorization.domain.clientauth;

import java.time.Instant;

/**
 * Port that remembers the identifiers ({@code jti}) of the client assertions already accepted, so an assertion cannot
 * be presented twice. Implementations never return {@code null}.
 */
public interface ClientAssertionReplayRegistry {

    /**
     * Records the first use of an assertion identifier of a client. Safe under concurrency: of several simultaneous
     * registrations of the same pair exactly one returns {@code true}.
     *
     * @param clientId  identifier of the client.
     * @param jti       the {@code jti} claim of the assertion.
     * @param expiresAt instant at which the assertion expires.
     * @return {@code true} only when the pair had not been registered before, {@code false} for a replay.
     */
    boolean register(String clientId, String jti, Instant expiresAt);

    /**
     * Forgets the identifiers of the assertions that expired at or before an instant.
     *
     * @param now the current instant.
     * @return the number of identifiers removed.
     */
    int purgeExpired(Instant now);
}
