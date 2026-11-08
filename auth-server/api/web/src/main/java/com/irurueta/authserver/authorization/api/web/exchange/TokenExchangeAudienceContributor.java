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

package com.irurueta.authserver.authorization.api.web.exchange;

import com.irurueta.authserver.authorization.api.web.tokens.IssuedTokenClaims;
import com.irurueta.authserver.authorization.api.web.tokens.JwtClaimsContributor;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.stereotype.Component;

// tag::exchange-claims[]
/**
 * Honours the {@code audience} parameter of a token exchange request, which the framework parses but ignores. The
 * audiences of an exchanged access token are those the exchanging client may have (its
 * {@value IssuedTokenClaims#AUDIENCES_SETTING} setting); when the request names audiences, only the ones among them
 * are kept. An audience outside the list of the client is simply not granted, and when none of the requested ones is
 * allowed the request is refused with {@value #INVALID_TARGET} (RFC 8693, section 2.2.2), so a narrowed request never
 * comes back with every audience of the client. Tokens of any other grant type are not touched.
 */
@Component
@Order(TokenExchangeAudienceContributor.ORDER)
public class TokenExchangeAudienceContributor implements JwtClaimsContributor {

    /** Order of the contributor: after the multi-factor ({@code 100}) and identity provider ({@code 110}) ones. */
    public static final int ORDER = 120;

    /** Error code of an unacceptable target (RFC 8693, section 2.2.2), which the framework has no constant for. */
    public static final String INVALID_TARGET = "invalid_target";

    @Override
    public void contribute(final OAuth2TokenContext context, final Map<String, Object> claims) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                || !AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())
                || !(context.getAuthorizationGrant() instanceof OAuth2TokenExchangeAuthenticationToken exchange)
                || exchange.getAudiences().isEmpty()) {
            return;
        }
        final var allowed = context.getRegisteredClient().getClientSettings()
                .<Object>getSetting(IssuedTokenClaims.AUDIENCES_SETTING) instanceof List<?> audiences
                ? audiences : List.of();
        // a mutable list on purpose: the authorization store only deserializes allow-listed types
        final var granted = allowed.stream().map(String::valueOf).filter(exchange.getAudiences()::contains)
                .collect(Collectors.toCollection(ArrayList::new));
        if (granted.isEmpty()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(INVALID_TARGET,
                    "None of the requested audiences is allowed for the client", null));
        }
        claims.put(OAuth2TokenClaimNames.AUD, granted);
    }
}
// end::exchange-claims[]
