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

package com.irurueta.authserver.authorization.application.clientauth;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.util.StringUtils;

/**
 * Settings of the client assertions, bound from {@code authserver.client-assertion.*} once and validated at startup.
 * A missing value takes its default, so the application starts without any setting.
 *
 * @param maxLifetime longest lifetime (exp minus iat, or exp minus now when iat is absent) an assertion may have
 *                    (default 5 minutes).
 * @param cleanup     the purge of the stored identifiers.
 */
@ConfigurationProperties("authserver.client-assertion")
public record ClientAssertionProperties(
        @DefaultValue("PT5M") Duration maxLifetime,
        @DefaultValue Cleanup cleanup) {

    /** Default longest lifetime of an assertion, in minutes. */
    private static final long DEFAULT_MAX_LIFETIME_MINUTES = 5L;

    /**
     * Applies the defaults and validates the settings.
     *
     * @throws IllegalArgumentException if the lifetime is zero or negative or the cron expression is invalid.
     */
    public ClientAssertionProperties {
        if (maxLifetime == null) {
            maxLifetime = Duration.ofMinutes(DEFAULT_MAX_LIFETIME_MINUTES);
        } else if (maxLifetime.isNegative() || maxLifetime.isZero()) {
            throw new IllegalArgumentException("authserver.client-assertion.max-lifetime must be positive");
        }
        if (cleanup == null) {
            cleanup = new Cleanup(null);
        }
    }

    /**
     * Settings of the purge of expired identifiers.
     *
     * @param cron Spring cron expression saying when the purge runs (default every hour at minute 30).
     */
    public record Cleanup(@DefaultValue("0 30 * * * *") String cron) {

        /** Default cron expression. */
        private static final String DEFAULT_CRON = "0 30 * * * *";

        /**
         * Applies the default and validates the expression.
         *
         * @throws IllegalArgumentException if the expression is not a valid Spring cron expression.
         */
        public Cleanup {
            if (!StringUtils.hasText(cron)) {
                cron = DEFAULT_CRON;
            }
            if (!CronExpression.isValidExpression(cron)) {
                throw new IllegalArgumentException("authserver.client-assertion.cleanup.cron is not a valid cron");
            }
        }
    }
}
