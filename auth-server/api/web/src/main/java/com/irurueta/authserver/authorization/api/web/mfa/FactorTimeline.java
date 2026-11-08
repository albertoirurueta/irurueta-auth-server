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
import com.irurueta.authserver.authorization.domain.mfa.MfaPolicy;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.stereotype.Component;

// tag::mfa-factor-timeline[]
/**
 * Reads, from the {@link FactorGrantedAuthority} instances of an authentication, the factors that prove something
 * about it and when they were presented. It is the single place the claims ({@link MfaClaimsContributor}) and the
 * step-up checks ({@link StepUpAuthorizationRequestConverter}) take {@code amr}, {@code acr} and {@code auth_time}
 * from, so both always agree:
 *
 * <ul>
 *   <li>only the factors of the {@link AuthenticationFactorRegistry} that {@link MfaPolicy#isReported} accepts count:
 *       a remembered (trusted) device does not;</li>
 *   <li>the authentication is multi-factor when {@link MfaPolicy#isMultiFactor} says so: at least two distinct
 *       factors count, or one counted factor proves a multi-factor authentication alone;</li>
 *   <li>{@code auth_time} is when the primary factor was presented (the earliest one when there are several), so a
 *       second factor added later never makes the sign-in look newer; without a primary factor it is the earliest
 *       counted factor.</li>
 * </ul>
 */
@Component
@RequiredArgsConstructor
public class FactorTimeline {

    /** Registry of the known factors. */
    private final AuthenticationFactorRegistry factorRegistry;

    /** Policy that tells which factors are reported and which are primary. */
    private final MfaPolicy mfaPolicy;

    /**
     * Lists the factor authorities of an authentication that count, oldest first.
     *
     * @param authentication the authentication.
     * @return the counted factor authorities, sorted by issue instant; empty when none.
     */
    public List<FactorGrantedAuthority> countedFactors(final Authentication authentication) {
        return factorsMatching(authentication, mfaPolicy::isReported);
    }

    /**
     * Lists the {@code amr} values of the counted factors, in the order they were presented, without duplicates.
     *
     * @param authentication the authentication.
     * @return the values; empty when no factor counts.
     */
    public List<String> amrValues(final Authentication authentication) {
        return countedFactors(authentication).stream()
                .map(authority -> factorRegistry.findByAuthority(authority.getAuthority()))
                .flatMap(Optional::stream)
                .map(AuthenticationFactor::amrValue)
                .distinct()
                .toList();
    }

    /**
     * Tells whether an authentication is multi-factor, by {@link MfaPolicy#isMultiFactor} over its counted factors.
     *
     * @param authentication the authentication.
     * @return {@code true} for a multi-factor authentication.
     */
    public boolean isMultiFactor(final Authentication authentication) {
        return mfaPolicy.isMultiFactor(countedFactors(authentication).stream()
                .map(authority -> factorRegistry.findByAuthority(authority.getAuthority()))
                .flatMap(Optional::stream)
                .collect(Collectors.toSet()));
    }

    /**
     * Finds the instant of the authentication, the one {@code auth_time} reports and {@code max_age} is measured
     * from.
     *
     * @param authentication the authentication.
     * @return the issue instant of the earliest primary factor, or else of the earliest counted factor; empty when no
     *         counted factor carries an instant.
     */
    public Optional<Instant> authTime(final Authentication authentication) {
        return earliest(factorsMatching(authentication,
                factor -> mfaPolicy.isReported(factor) && mfaPolicy.isPrimary(factor)))
                .or(() -> earliest(countedFactors(authentication)));
    }

    /**
     * Lists the factor authorities of an authentication whose registered factor passes a test, oldest first.
     *
     * @param authentication the authentication.
     * @param test           the test of the registered factor.
     * @return the matching authorities.
     */
    private List<FactorGrantedAuthority> factorsMatching(final Authentication authentication,
            final Predicate<AuthenticationFactor> test) {
        return authentication.getAuthorities().stream()
                .filter(FactorGrantedAuthority.class::isInstance)
                .map(FactorGrantedAuthority.class::cast)
                .filter(authority -> factorRegistry.findByAuthority(authority.getAuthority()).filter(test).isPresent())
                .sorted(Comparator.comparing(FactorGrantedAuthority::getIssuedAt,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();
    }

    /**
     * Finds the earliest issue instant of some factor authorities.
     *
     * @param factors the authorities.
     * @return the earliest instant, or empty when none carries one.
     */
    private static Optional<Instant> earliest(final List<FactorGrantedAuthority> factors) {
        return factors.stream().map(FactorGrantedAuthority::getIssuedAt).filter(Objects::nonNull)
                .min(Comparator.naturalOrder());
    }
}
// end::mfa-factor-timeline[]
