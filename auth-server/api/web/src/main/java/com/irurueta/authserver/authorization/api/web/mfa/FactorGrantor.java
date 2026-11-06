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

import java.time.Clock;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * Adds the authority of a verified factor to an authentication. Authentications are immutable, so a new one is built
 * that keeps the principal and the authorities of the original and carries the new factor, stamped with the current
 * time (which is what {@code auth_time} and {@code max_age} are measured with).
 */
@Component
@RequiredArgsConstructor
public class FactorGrantor {

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Grants a factor.
     *
     * @param authentication the authentication to start from.
     * @param authority      authority of the factor ({@code FACTOR_} prefix included).
     * @return a new authentication with the factor added; the same one when it already holds it.
     */
    public Authentication grant(final Authentication authentication, final String authority) {
        final var present = authentication.getAuthorities().stream()
                .anyMatch(granted -> authority.equals(granted.getAuthority()));
        if (present) {
            return authentication;
        }
        final var factor = FactorGrantedAuthority.withAuthority(authority).issuedAt(clock.instant()).build();
        return authentication.toBuilder().authorities(authorities -> authorities.add(factor)).build();
    }
}
