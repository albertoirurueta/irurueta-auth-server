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

package com.irurueta.authserver.authorization.application.ott;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Settings of the one-time codes, bound from {@code authserver.ott.*} once and validated at startup. A missing (or
 * zero, for a number) value takes its default, so the application starts without any setting.
 *
 * @param codeLength  number of digits of a code (default 6).
 * @param codeTtl     how long a code is valid (default 10 minutes).
 * @param linkTtl     how long a magic link is valid (default 15 minutes).
 * @param maxAttempts verification attempts a code allows before it is burnt (default 5).
 */
@ConfigurationProperties("authserver.ott")
public record OttProperties(
        @DefaultValue("6") int codeLength,
        @DefaultValue("PT10M") Duration codeTtl,
        @DefaultValue("PT15M") Duration linkTtl,
        @DefaultValue("5") int maxAttempts) {

    /** Default number of digits of a code. */
    private static final int DEFAULT_CODE_LENGTH = 6;

    /** Default validity of a code, in minutes. */
    private static final long DEFAULT_CODE_TTL_MINUTES = 10L;

    /** Default validity of a link, in minutes. */
    private static final long DEFAULT_LINK_TTL_MINUTES = 15L;

    /** Default number of verification attempts. */
    private static final int DEFAULT_MAX_ATTEMPTS = 5;

    /**
     * Applies the defaults and validates the settings.
     *
     * @throws IllegalArgumentException if the length or the attempts are negative or a duration is negative.
     */
    public OttProperties {
        codeLength = positiveOrDefault(codeLength, DEFAULT_CODE_LENGTH, "code-length");
        maxAttempts = positiveOrDefault(maxAttempts, DEFAULT_MAX_ATTEMPTS, "max-attempts");
        codeTtl = positiveOrDefault(codeTtl, Duration.ofMinutes(DEFAULT_CODE_TTL_MINUTES), "code-ttl");
        linkTtl = positiveOrDefault(linkTtl, Duration.ofMinutes(DEFAULT_LINK_TTL_MINUTES), "link-ttl");
    }

    /**
     * Keeps a positive number, replaces zero by its default and rejects a negative one.
     *
     * @param value        the configured number.
     * @param defaultValue the default.
     * @param key          the key of the setting below {@code authserver.ott}.
     * @return the value to use.
     */
    private static int positiveOrDefault(final int value, final int defaultValue, final String key) {
        if (value < 0) {
            throw new IllegalArgumentException("authserver.ott." + key + " must be positive");
        }
        return value == 0 ? defaultValue : value;
    }

    /**
     * Keeps a positive duration, replaces a missing or zero one by its default and rejects a negative one.
     *
     * @param value        the configured duration.
     * @param defaultValue the default.
     * @param key          the key of the setting below {@code authserver.ott}.
     * @return the duration to use.
     */
    private static Duration positiveOrDefault(final Duration value, final Duration defaultValue, final String key) {
        if (value != null && value.isNegative()) {
            throw new IllegalArgumentException("authserver.ott." + key + " must be positive");
        }
        return value == null || value.isZero() ? defaultValue : value;
    }
}
