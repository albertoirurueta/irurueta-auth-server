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

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Configuration of the limit on the attempts to verify a user code ({@code authserver.device.rate-limit.*}): the user
 * code is short, so the attempts a signed-in user and a client address may make in a window are bounded, on top of the
 * expiry of the code itself.
 *
 * @param enabled        whether attempts are limited at all (default {@code true}).
 * @param window         length of the fixed window the attempts are counted in (default 15 minutes).
 * @param perClient      attempts one client address may make in a window (default 30).
 * @param perUser        attempts one signed-in user may make in a window (default 10).
 * @param maxTrackedKeys keys tracked at most per kind of limit; the oldest is forgotten first, so the memory used
 *                       stays bounded (default 10 000).
 */
@ConfigurationProperties(prefix = "authserver.device.rate-limit")
public record DeviceRateLimitProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("PT15M") Duration window,
        @DefaultValue("30") int perClient,
        @DefaultValue("10") int perUser,
        @DefaultValue("10000") int maxTrackedKeys) {

    /**
     * Validates the configuration.
     *
     * @throws IllegalArgumentException if the window is not positive, or a limit or the number of tracked keys is not
     *                                  positive.
     */
    public DeviceRateLimitProperties {
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be positive");
        }
        if (perClient < 1 || perUser < 1 || maxTrackedKeys < 1) {
            throw new IllegalArgumentException("limits and maxTrackedKeys must be positive");
        }
    }
}
