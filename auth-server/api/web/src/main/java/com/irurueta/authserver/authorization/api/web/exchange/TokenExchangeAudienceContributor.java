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
 * allowed the audiences of the client stay as they are. Tokens of any other grant type are not touched.
 */
@Component
@Order(TokenExchangeAudienceContributor.ORDER)
public class TokenExchangeAudienceContributor implements JwtClaimsContributor {

    /** Order of the contributor: after the multi-factor ({@code 100}) and identity provider ({@code 110}) ones. */
    public static final int ORDER = 120;

    @Override
    public void contribute(final OAuth2TokenContext context, final Map<String, Object> claims) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                || !AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())
                || !(context.getAuthorizationGrant() instanceof OAuth2TokenExchangeAuthenticationToken exchange)
                || exchange.getAudiences().isEmpty()) {
            return;
        }
        if (!(context.getRegisteredClient().getClientSettings().getSetting(IssuedTokenClaims.AUDIENCES_SETTING)
                instanceof List<?> allowed)) {
            return;
        }
        // a mutable list on purpose: the authorization store only deserializes allow-listed types
        final var granted = allowed.stream().map(String::valueOf).filter(exchange.getAudiences()::contains)
                .collect(Collectors.toCollection(ArrayList::new));
        if (!granted.isEmpty()) {
            claims.put(OAuth2TokenClaimNames.AUD, granted);
        }
    }
}
// end::exchange-claims[]
