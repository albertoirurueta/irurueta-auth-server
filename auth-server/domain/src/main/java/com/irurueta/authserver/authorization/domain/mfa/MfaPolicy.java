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

    /**
     * Tells whether a set of factors satisfies the policy: a {@link FactorStrength#PRIMARY_STRONG} factor alone, or a
     * {@link FactorStrength#PRIMARY} factor together with a {@link FactorStrength#SECOND} one.
     *
     * @param factors the factors used by the authentication; must not be {@code null}.
     * @return {@code true} when the factors are enough.
     */
    public boolean isSatisfied(final Set<AuthenticationFactor> factors) {
        return hasStrength(factors, FactorStrength.PRIMARY_STRONG)
                || hasStrength(factors, FactorStrength.PRIMARY) && hasStrength(factors, FactorStrength.SECOND);
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
