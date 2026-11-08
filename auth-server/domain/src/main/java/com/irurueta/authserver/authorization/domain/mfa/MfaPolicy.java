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
package com.irurueta.authserver.authorization.domain.mfa;

import java.util.Set;

/**
 * The rule that decides when the factors of an authentication are enough, and when they are required. It is pure: it
 * knows nothing about sessions, requests or storage.
 */
public class MfaPolicy {

    /** Minimum number of distinct reported factors of a multi-factor authentication. */
    public static final int MIN_MULTI_FACTORS = 2;

    /**
     * Tells whether a set of factors satisfies the sign-in policy: a {@link FactorStrength#PRIMARY_STRONG} factor
     * alone, or a {@link FactorStrength#PRIMARY} factor together with a {@link FactorStrength#SECOND} or a
     * {@link FactorStrength#REMEMBERED} one (a trusted device skips the second factor of a sign-in).
     *
     * @param factors the factors used by the authentication; must not be {@code null}.
     * @return {@code true} when the factors are enough.
     */
    public boolean isSatisfied(final Set<AuthenticationFactor> factors) {
        return hasStrength(factors, FactorStrength.PRIMARY_STRONG)
                || hasStrength(factors, FactorStrength.PRIMARY) && (hasStrength(factors, FactorStrength.SECOND)
                || hasStrength(factors, FactorStrength.REMEMBERED));
    }

    /**
     * Tells whether a factor proves something about the authentication it was presented in, and is therefore reported
     * ({@code amr}, {@code acr}, {@code auth_time}) and counted by a step-up request. A
     * {@link FactorStrength#REMEMBERED} factor is not: it only recalls a second factor presented earlier.
     *
     * @param factor the factor.
     * @return {@code true} unless the factor is {@link FactorStrength#REMEMBERED}.
     */
    public boolean isReported(final AuthenticationFactor factor) {
        return factor.strength() != FactorStrength.REMEMBERED;
    }

    /**
     * Tells whether the factors of an authentication make it multi-factor, the one rule behind the {@code amr}
     * {@code mfa} value, the multi-factor {@code acr} and every step-up check: at least {@link #MIN_MULTI_FACTORS}
     * distinct reported factors, or one reported factor that proves a multi-factor authentication alone
     * ({@link AuthenticationFactor#multiFactor()}). A {@link FactorStrength#PRIMARY_STRONG} factor alone satisfies
     * the sign-in policy ({@link #isSatisfied}) but is multi-factor only when it says so: a passkey or a certificate
     * proves one thing, however strongly.
     *
     * @param factors the factors used by the authentication; must not be {@code null}.
     * @return {@code true} for a multi-factor authentication.
     */
    public boolean isMultiFactor(final Set<AuthenticationFactor> factors) {
        final var reported = factors.stream().filter(this::isReported).toList();
        return reported.size() >= MIN_MULTI_FACTORS || reported.stream().anyMatch(AuthenticationFactor::multiFactor);
    }

    /**
     * Tells whether a factor is the primary one of an authentication, the one {@code auth_time} and {@code max_age}
     * are measured from.
     *
     * @param factor the factor.
     * @return {@code true} for a {@link FactorStrength#PRIMARY} or {@link FactorStrength#PRIMARY_STRONG} factor.
     */
    public boolean isPrimary(final AuthenticationFactor factor) {
        return factor.strength() == FactorStrength.PRIMARY || factor.strength() == FactorStrength.PRIMARY_STRONG;
    }

    /**
     * Tells whether multi-factor authentication is required, which is when either the client or the user demands it.
     *
     * @param clientRequires whether the client being served requires it.
     * @param userRequires   whether the user's account requires it.
     * @return {@code true} when a second factor is required.
     */
    public boolean isRequired(final boolean clientRequires, final boolean userRequires) {
        return clientRequires || userRequires;
    }

    /**
     * Tells whether any factor has a strength.
     *
     * @param factors  the factors to inspect.
     * @param strength the strength to look for.
     * @return {@code true} when at least one factor has that strength.
     */
    private static boolean hasStrength(final Set<AuthenticationFactor> factors, final FactorStrength strength) {
        return factors.stream().anyMatch(factor -> factor.strength() == strength);
    }
}
