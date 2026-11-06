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

package com.irurueta.authserver.authorization.api.web.mfa;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Registry of the authentication factors this server knows. Every {@link AuthenticationFactor} bean is registered, so
 * a new login method adds its factor by declaring a bean, without editing shared files. The class is final because its
 * constructor validates (and may throw), which would otherwise leave a partially built subclass instance observable.
 */
public final class AuthenticationFactorRegistry {

    /** Registered factors by the authority that proves them, in registration order. */
    private final Map<String, AuthenticationFactor> byAuthority = new LinkedHashMap<>();

    /**
     * Creates the registry.
     *
     * @param factors the factors to register.
     * @throws IllegalArgumentException if two factors share an authority.
     */
    public AuthenticationFactorRegistry(final List<AuthenticationFactor> factors) {
        for (final var factor : factors) {
            if (byAuthority.putIfAbsent(factor.authority(), factor) != null) {
                throw new IllegalArgumentException("Authority registered twice: " + factor.authority());
            }
        }
    }

    /**
     * Lists every registered factor.
     *
     * @return the factors, in registration order.
     */
    public List<AuthenticationFactor> all() {
        return List.copyOf(byAuthority.values());
    }

    /**
     * Finds the factor proved by an authority.
     *
     * @param authority the authority, for example {@code FACTOR_PASSWORD}.
     * @return the factor, or an empty optional when none is registered for it.
     */
    public Optional<AuthenticationFactor> findByAuthority(final String authority) {
        return Optional.ofNullable(byAuthority.get(authority));
    }

    /**
     * Lists the registered factors that have a strength.
     *
     * @param strength the strength to look for.
     * @return the factors, in registration order.
     */
    public List<AuthenticationFactor> withStrength(final FactorStrength strength) {
        return byAuthority.values().stream().filter(factor -> factor.strength() == strength).toList();
    }

    /**
     * Tells which registered factors an authentication has presented.
     *
     * @param authentication the authentication; its authorities that match a registered factor count.
     * @return the factors used, empty when none.
     */
    public Set<AuthenticationFactor> factorsOf(final Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(byAuthority::get)
                .filter(Objects::nonNull)
                .collect(Collectors.toUnmodifiableSet());
    }
}
