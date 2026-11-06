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
import java.util.ArrayList;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.stereotype.Component;

// tag::mfa-claims[]
/**
 * Adds to the access and ID tokens how the user authenticated: {@code amr} (the RFC 8176 values of the factors really
 * presented, plus {@code mfa} when there are at least two), {@code acr} (the class of the authentication, see
 * {@link AuthenticationContextClass}) and {@code auth_time} (the epoch second the primary factor was presented, a
 * number per OIDC; access tokens only, because the framework sets it on ID tokens). Every value comes from the
 * {@link FactorTimeline}, which reads the {@link org.springframework.security.core.authority.FactorGrantedAuthority}
 * instances of the principal: authorities of an unknown factor and of a remembered (trusted) device are ignored, so a
 * browser that skipped the second factor gets {@code amr [pwd]} and the password class. A token with no counted factor
 * (for example of the client credentials grant) gets none of the claims.
 */
@Component
@Order(MfaClaimsContributor.ORDER)
@RequiredArgsConstructor
public class MfaClaimsContributor implements JwtClaimsContributor {

    /** Order of the contributor: after the built-in claims and the default contributors. */
    public static final int ORDER = 100;

    /** RFC 8176 {@code amr} value that tells that more than one factor was used. */
    public static final String MULTI_FACTOR_AMR_VALUE = "mfa";

    /** Reads the counted factors of the principal and their instants. */
    private final FactorTimeline factorTimeline;

    @Override
    public void contribute(final OAuth2TokenContext context, final Map<String, Object> claims) {
        final var principal = context.getPrincipal();
        if (principal == null) {
            return;
        }
        final var authTime = factorTimeline.authTime(principal);
        if (authTime.isEmpty()) {
            return;
        }
        // a mutable list on purpose: the authorization store only deserializes allow-listed types
        final var amr = new ArrayList<String>(factorTimeline.amrValues(principal));
        final var multiFactor = factorTimeline.isMultiFactor(principal);
        if (multiFactor) {
            amr.add(MULTI_FACTOR_AMR_VALUE);
        }
        claims.put(IdTokenClaimNames.AMR, amr);
        claims.put(IdTokenClaimNames.ACR,
                multiFactor ? AuthenticationContextClass.MULTI_FACTOR : AuthenticationContextClass.PASSWORD);
        // the framework sets auth_time itself on ID tokens (as a date it expects to read back on refresh)
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            claims.put(IdTokenClaimNames.AUTH_TIME, authTime.get().getEpochSecond());
        }
    }
}
// end::mfa-claims[]
