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
package com.irurueta.authserver.authorization.domain.sms;

import java.time.Duration;
import java.util.Map;
import java.util.Set;

/**
 * The rules that keep text messages from costing too much: the countries messages may go to, what a message costs in
 * each and the budget per window and per day. It is pure: the spend is kept by a {@link SmsCostLedgerRepository}.
 */
public final class SmsCostPolicy {

    /** Length of the window of the daily budget. */
    public static final Duration DAY = Duration.ofDays(1);

    /** Countries that may receive messages, as upper-case ISO alpha-2 codes. */
    private final Set<String> allowedCountries;

    /** Cost of a message per country, in millionths of the budget currency. */
    private final Map<String, Long> costMicrosByCountry;

    /** Cost of a message to an allowed country with no cost of its own. */
    private final long defaultCostMicros;

    /** Length of the short window. */
    private final Duration window;

    /** Budget of the short window. */
    private final long windowCapMicros;

    /** Budget of a day. */
    private final long dailyCapMicros;

    /**
     * Creates the policy.
     *
     * @param allowedCountries    countries that may receive messages; empty allows none.
     * @param costMicrosByCountry cost of a message per country; not negative values.
     * @param defaultCostMicros   cost of a message to an allowed country that has none of its own; not negative.
     * @param window              length of the short window; positive.
     * @param windowCapMicros     budget of the short window; not negative.
     * @param dailyCapMicros      budget of a day; not negative.
     * @throws IllegalArgumentException if a value is missing, a country is not an ISO alpha-2 code, or a cost, cap or
     *                                  the window is out of range.
     */
    public SmsCostPolicy(
            final Set<String> allowedCountries,
            final Map<String, Long> costMicrosByCountry,
            final long defaultCostMicros,
            final Duration window,
            final long windowCapMicros,
            final long dailyCapMicros) {
        if (allowedCountries == null || costMicrosByCountry == null) {
            throw new IllegalArgumentException("countries and costs must not be null");
        }
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be positive");
        }
        if (defaultCostMicros < 0 || windowCapMicros < 0 || dailyCapMicros < 0) {
            throw new IllegalArgumentException("costs and caps must not be negative");
        }
        allowedCountries.forEach(SmsCostPolicy::requireCountry);
        costMicrosByCountry.forEach((country, cost) -> {
            requireCountry(country);
            if (cost == null || cost < 0) {
                throw new IllegalArgumentException("cost of " + country + " must not be negative");
            }
        });
        this.allowedCountries = Set.copyOf(allowedCountries);
        this.costMicrosByCountry = Map.copyOf(costMicrosByCountry);
        this.defaultCostMicros = defaultCostMicros;
        this.window = window;
        this.windowCapMicros = windowCapMicros;
        this.dailyCapMicros = dailyCapMicros;
    }

    /**
     * Tells whether messages may be sent to a country.
     *
     * @param country ISO alpha-2 code of the country, or {@code null}.
     * @return {@code true} when the country is allowed.
     */
    public boolean isCountryAllowed(final String country) {
        return country != null && allowedCountries.contains(country);
    }

    /**
     * Gets what a message to a country costs.
     *
     * @param country ISO alpha-2 code of the country.
     * @return the cost in millionths of the budget currency; the default when the country has none of its own.
     */
    public long costMicros(final String country) {
        return costMicrosByCountry.getOrDefault(country, defaultCostMicros);
    }

    /**
     * Gets the length of the short window the window budget applies to.
     *
     * @return the window.
     */
    public Duration window() {
        return window;
    }

    /**
     * Gets the cap of the short window, as the ledger checks it.
     *
     * @return the window and its budget.
     */
    public SmsSpendCap windowCap() {
        return new SmsSpendCap(window, windowCapMicros);
    }

    /**
     * Gets the cap of a day, as the ledger checks it.
     *
     * @return {@link #DAY} and its budget.
     */
    public SmsSpendCap dailyCap() {
        return new SmsSpendCap(DAY, dailyCapMicros);
    }

    /**
     * Tells whether the spend of the short window is within its budget.
     *
     * @param spentMicros spend in the window, the message being sent included.
     * @return {@code true} when the spend does not exceed the budget.
     */
    public boolean isWithinWindowCap(final long spentMicros) {
        return spentMicros <= windowCapMicros;
    }

    /**
     * Tells whether the spend of the last day is within its budget.
     *
     * @param spentMicros spend in the last day, the message being sent included.
     * @return {@code true} when the spend does not exceed the budget.
     */
    public boolean isWithinDailyCap(final long spentMicros) {
        return spentMicros <= dailyCapMicros;
    }

    /**
     * Rejects anything but an upper-case ISO 3166-1 alpha-2 code.
     *
     * @param country value to check.
     */
    private static void requireCountry(final String country) {
        if (country == null || !country.matches("[A-Z]{2}")) {
            throw new IllegalArgumentException("country must be an upper-case ISO 3166-1 alpha-2 code");
        }
    }
}
