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

import com.irurueta.authserver.authorization.api.web.tokens.JwtClaimsContributor;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.stereotype.Component;

/**
 * Adds to the access and ID tokens how the user authenticated: {@code amr} (the RFC 8176 values of the factors really
 * presented, plus {@code mfa} when there are at least two), {@code acr} (the class of the authentication, see
 * {@link AuthenticationContextClass}) and {@code auth_time}
 * (the epoch second the last factor was presented, a number per OIDC; access tokens only, because the framework
 * sets it on ID tokens). The
 * factors are read from the {@link FactorGrantedAuthority} instances of the principal and mapped through the
 * {@link AuthenticationFactorRegistry}; authorities of an unknown factor are ignored. A token with no factor (for
 * example of the client credentials grant) gets none of the claims.
 */
@Component
@Order(MfaClaimsContributor.ORDER)
@RequiredArgsConstructor
public class MfaClaimsContributor implements JwtClaimsContributor {

    /** Order of the contributor: after the built-in claims and the default contributors. */
    public static final int ORDER = 100;

    /** RFC 8176 {@code amr} value that tells that more than one factor was used. */
    public static final String MULTI_FACTOR_AMR_VALUE = "mfa";

    /** Minimum number of distinct factors of a multi-factor authentication. */
    private static final int MIN_MULTI_FACTORS = 2;

    /** Registry of the known factors. */
    private final AuthenticationFactorRegistry factorRegistry;

    @Override
    public void contribute(final OAuth2TokenContext context, final Map<String, Object> claims) {
        final var principal = context.getPrincipal();
        if (principal == null) {
            return;
        }
        final var granted = principal.getAuthorities().stream()
                .filter(FactorGrantedAuthority.class::isInstance)
                .map(FactorGrantedAuthority.class::cast)
                .filter(authority -> factorRegistry.findByAuthority(authority.getAuthority()).isPresent())
                .sorted(Comparator.comparing(FactorGrantedAuthority::getIssuedAt))
                .toList();
        if (granted.isEmpty()) {
            return;
        }
        // mutable lists on purpose: the authorization store only deserializes allow-listed types
        final var amr = new ArrayList<String>(granted.stream()
                .map(authority -> factorRegistry.findByAuthority(authority.getAuthority()))
                .flatMap(Optional::stream)
                .map(AuthenticationFactor::amrValue)
                .distinct()
                .toList());
        final var multiFactor = granted.stream().map(FactorGrantedAuthority::getAuthority).distinct().count()
                >= MIN_MULTI_FACTORS;
        if (multiFactor) {
            amr.add(MULTI_FACTOR_AMR_VALUE);
        }
        claims.put(IdTokenClaimNames.AMR, amr);
        claims.put(IdTokenClaimNames.ACR,
                multiFactor ? AuthenticationContextClass.MULTI_FACTOR : AuthenticationContextClass.PASSWORD);
        // the framework sets auth_time itself on ID tokens (as a date it expects to read back on refresh)
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            claims.put(IdTokenClaimNames.AUTH_TIME, lastIssuedAt(granted).getEpochSecond());
        }
    }

    /**
     * Finds the instant the last factor was presented.
     *
     * @param granted the factor authorities, never empty.
     * @return the latest issue instant.
     */
    private static Instant lastIssuedAt(final List<FactorGrantedAuthority> granted) {
        return granted.stream().map(FactorGrantedAuthority::getIssuedAt).filter(Objects::nonNull)
                .max(Comparator.naturalOrder()).orElseThrow();
    }
}
