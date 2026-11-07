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

package com.irurueta.authserver.authorization.application.sms;

import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Settings of the SMS channel, bound from {@code authserver.sms.*} once and validated at startup. A missing (or zero,
 * for a number) value takes its default, so the application starts without any setting.
 *
 * <p>Costs and caps are in micros of the billing currency (one millionth), so they stay integers.
 *
 * @param defaultRegion            ISO 3166-1 region assumed for a number typed without a country code (default
 *                                 {@code US}).
 * @param allowedCountries         ISO 3166-1 regions an SMS may be sent to (default {@code US}, {@code ES},
 *                                 {@code GB}).
 * @param costPerCountryMicros     cost of one SMS by region; a region absent here costs {@code defaultCostMicros}.
 * @param defaultCostMicros        cost of an SMS to a region without its own cost (default 50000).
 * @param window                   length of the spending window (default one hour).
 * @param windowCapMicros          spending allowed in a window (default 5000000).
 * @param dailyCapMicros           spending allowed in 24 hours (default 20000000).
 * @param verificationCodeLength   digits of the code that verifies a phone (default 6).
 * @param verificationCodeTtl      how long that code is valid (default 10 minutes).
 * @param verificationMaxAttempts  attempts allowed for that code (default 5).
 * @param ledgerRetention          how long the cost ledger keeps its rows, at least one day (default 2 days).
 */
@ConfigurationProperties("authserver.sms")
public record SmsProperties(
        @DefaultValue("US") String defaultRegion,
        @DefaultValue({"US", "ES", "GB"}) Set<String> allowedCountries,
        Map<String, Long> costPerCountryMicros,
        @DefaultValue("50000") long defaultCostMicros,
        @DefaultValue("PT1H") Duration window,
        @DefaultValue("5000000") long windowCapMicros,
        @DefaultValue("20000000") long dailyCapMicros,
        @DefaultValue("6") int verificationCodeLength,
        @DefaultValue("PT10M") Duration verificationCodeTtl,
        @DefaultValue("5") int verificationMaxAttempts,
        @DefaultValue("P2D") Duration ledgerRetention) {

    /** Default region. */
    private static final String DEFAULT_REGION = "US";

    /** Default allowed regions. */
    private static final Set<String> DEFAULT_COUNTRIES = Set.of("US", "ES", "GB");

    /** Default spending window, in minutes. */
    private static final long DEFAULT_WINDOW_MINUTES = 60L;

    /** Default digits of the verification code. */
    private static final int DEFAULT_CODE_LENGTH = 6;

    /** Default validity of the verification code, in minutes. */
    private static final long DEFAULT_CODE_TTL_MINUTES = 10L;

    /** Default attempts of the verification code. */
    private static final int DEFAULT_MAX_ATTEMPTS = 5;

    /** Default retention of the ledger, in days. */
    private static final long DEFAULT_RETENTION_DAYS = 2L;

    /** Pattern of a region code. */
    private static final String REGION_PATTERN = "[A-Z]{2}";

    /**
     * Applies the defaults and validates the settings.
     *
     * @throws IllegalArgumentException if a region is not an upper-case ISO code, a cost or cap is negative, a
     *                                  number or duration is negative, or the retention is shorter than one day.
     */
    public SmsProperties {
        defaultRegion = defaultRegion == null || defaultRegion.isBlank() ? DEFAULT_REGION : defaultRegion;
        requireRegion(defaultRegion, "default-region");
        allowedCountries = allowedCountries == null ? DEFAULT_COUNTRIES : Set.copyOf(allowedCountries);
        allowedCountries.forEach(region -> requireRegion(region, "allowed-countries"));
        costPerCountryMicros = costPerCountryMicros == null ? Map.of() : Map.copyOf(costPerCountryMicros);
        costPerCountryMicros.forEach((region, cost) -> {
            requireRegion(region, "cost-per-country-micros");
            requireNotNegative(cost, "cost-per-country-micros." + region);
        });
        requireNotNegative(defaultCostMicros, "default-cost-micros");
        requireNotNegative(windowCapMicros, "window-cap-micros");
        requireNotNegative(dailyCapMicros, "daily-cap-micros");
        window = durationOrDefault(window, Duration.ofMinutes(DEFAULT_WINDOW_MINUTES), "window");
        verificationCodeTtl = durationOrDefault(verificationCodeTtl, Duration.ofMinutes(DEFAULT_CODE_TTL_MINUTES),
                "verification-code-ttl");
        ledgerRetention = durationOrDefault(ledgerRetention, Duration.ofDays(DEFAULT_RETENTION_DAYS),
                "ledger-retention");
        if (ledgerRetention.compareTo(Duration.ofDays(1)) < 0) {
            throw new IllegalArgumentException("authserver.sms.ledger-retention must be at least one day");
        }
        verificationCodeLength = numberOrDefault(verificationCodeLength, DEFAULT_CODE_LENGTH,
                "verification-code-length");
        verificationMaxAttempts = numberOrDefault(verificationMaxAttempts, DEFAULT_MAX_ATTEMPTS,
                "verification-max-attempts");
    }

    /**
     * Rejects a value that is not an upper-case ISO region code.
     *
     * @param region the value.
     * @param key    the key of the setting below {@code authserver.sms}.
     */
    private static void requireRegion(final String region, final String key) {
        if (region == null || !region.matches(REGION_PATTERN)) {
            throw new IllegalArgumentException("authserver.sms." + key + " must hold upper-case ISO 3166-1 codes");
        }
    }

    /**
     * Rejects a negative amount.
     *
     * @param value the amount.
     * @param key   the key of the setting below {@code authserver.sms}.
     */
    private static void requireNotNegative(final Long value, final String key) {
        if (value == null || value < 0) {
            throw new IllegalArgumentException("authserver.sms." + key + " must not be negative");
        }
    }

    /**
     * Keeps a positive number, replaces zero by its default and rejects a negative one.
     *
     * @param value        the configured number.
     * @param defaultValue the default.
     * @param key          the key of the setting below {@code authserver.sms}.
     * @return the number to use.
     */
    private static int numberOrDefault(final int value, final int defaultValue, final String key) {
        if (value < 0) {
            throw new IllegalArgumentException("authserver.sms." + key + " must be positive");
        }
        return value == 0 ? defaultValue : value;
    }

    /**
     * Keeps a positive duration, replaces a missing or zero one by its default and rejects a negative one.
     *
     * @param value        the configured duration.
     * @param defaultValue the default.
     * @param key          the key of the setting below {@code authserver.sms}.
     * @return the duration to use.
     */
    private static Duration durationOrDefault(final Duration value, final Duration defaultValue, final String key) {
        if (value != null && value.isNegative()) {
            throw new IllegalArgumentException("authserver.sms." + key + " must be positive");
        }
        return value == null || value.isZero() ? defaultValue : value;
    }
}
