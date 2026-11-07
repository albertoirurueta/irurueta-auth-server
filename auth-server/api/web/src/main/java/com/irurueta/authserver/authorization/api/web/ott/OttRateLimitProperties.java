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
package com.irurueta.authserver.authorization.api.web.ott;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Configuration of the rate limiting of the one-time token endpoints ({@code authserver.ott.rate-limit.*}): the
 * requests for a token ({@code POST /ott/generate}, the phone enrolment) and the submissions of a token or a code
 * ({@code POST /login/ott}, {@code POST /login/second-factor/ott}, the phone verification).
 *
 * @param enabled                   whether requests are limited at all (default {@code true}).
 * @param window                    length of the fixed window the requests are counted in (default 15 minutes).
 * @param generationPerClient       tokens one client address may request in a window (default 20).
 * @param generationPerIdentifier   tokens that may be requested for one identifier in a window (default 5).
 * @param verificationPerClient     submissions one client address may make in a window (default 30).
 * @param verificationPerIdentifier submissions that may name one identifier in a window (default 10).
 * @param maxTrackedKeys            keys tracked at most per kind of limit; the oldest is forgotten first, so the memory
 *                                  used stays bounded (default 10 000).
 */
@ConfigurationProperties(prefix = "authserver.ott.rate-limit")
public record OttRateLimitProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("PT15M") Duration window,
        @DefaultValue("20") int generationPerClient,
        @DefaultValue("5") int generationPerIdentifier,
        @DefaultValue("30") int verificationPerClient,
        @DefaultValue("10") int verificationPerIdentifier,
        @DefaultValue("10000") int maxTrackedKeys) {

    /**
     * Validates the configuration.
     *
     * @throws IllegalArgumentException if the window is not positive, or a limit or the number of tracked keys is
     *                                  not positive.
     */
    public OttRateLimitProperties {
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be positive");
        }
        if (generationPerClient < 1 || generationPerIdentifier < 1 || verificationPerClient < 1
                || verificationPerIdentifier < 1 || maxTrackedKeys < 1) {
            throw new IllegalArgumentException("limits and maxTrackedKeys must be positive");
        }
    }
}
