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
package com.irurueta.authserver.authorization.api.web.implicit;

import com.irurueta.authserver.authorization.api.web.ratelimit.FixedWindowBuckets;
import java.time.Clock;

// tag::device-rate-limit[]
/**
 * Rate limiter of the attempts to verify a user code, on the pattern of the other limiters of this server: Bucket4j
 * token buckets in Caffeine caches ({@link FixedWindowBuckets}), one per client address and one per signed-in user, so
 * a user code, which is short, cannot be guessed faster than the limits allow. The buckets live in this instance
 * only: several instances each apply the limits on their own. The client address is
 * {@code request.getRemoteAddr()}, so behind a proxy {@code server.forward-headers-strategy} must be set for it to be
 * the real client.
 */
public final class DeviceVerificationRateLimiter {

    /** Key used when the client address is unknown. */
    private static final String UNKNOWN_CLIENT = "unknown";

    /** Limits, window and bound of the tracked keys. */
    private final DeviceRateLimitProperties properties;

    /** Buckets per client address. */
    private final FixedWindowBuckets clients;

    /** Buckets per signed-in user. */
    private final FixedWindowBuckets users;

    /**
     * Creates the limiter.
     *
     * @param properties limits, window and bound of the tracked keys.
     * @param clock      source of the current time.
     */
    public DeviceVerificationRateLimiter(final DeviceRateLimitProperties properties, final Clock clock) {
        this.properties = properties;
        clients = new FixedWindowBuckets(clock, properties.window(), properties.maxTrackedKeys());
        users = new FixedWindowBuckets(clock, properties.window(), properties.maxTrackedKeys());
    }

    /**
     * Counts one attempt and rejects it once a limit is exceeded.
     *
     * @param clientAddress address of the calling client, may be {@code null}.
     * @param userName      name of the signed-in user.
     * @throws DeviceVerificationRateLimitedException if the client address or the user exceeded its limit.
     */
    public void check(final String clientAddress, final String userName) {
        if (!properties.enabled()) {
            return;
        }
        final var clientWait = clients.tryConsume(clientAddress == null ? UNKNOWN_CLIENT : clientAddress,
                properties.perClient());
        if (clientWait.isPresent()) {
            throw new DeviceVerificationRateLimitedException(clientWait.get());
        }
        final var userWait = users.tryConsume(userName, properties.perUser());
        if (userWait.isPresent()) {
            throw new DeviceVerificationRateLimitedException(userWait.get());
        }
    }
}
// end::device-rate-limit[]
