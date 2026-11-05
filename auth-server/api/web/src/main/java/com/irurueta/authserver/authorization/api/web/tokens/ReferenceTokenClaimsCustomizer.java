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

package com.irurueta.authserver.authorization.api.web.tokens;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

// tag::tokens-reference-customizer[]
/**
 * Adds the claims of {@link IssuedTokenClaims} to the reference (opaque) access tokens. Such a token carries no
 * claims itself: the claims are stored with the authorization and returned by the introspection endpoint, so a
 * resource server that introspects it sees the same {@code roles}, {@code tenant}, {@code aud} and contributed
 * claims as one that decodes a JWT. It is the one {@code OAuth2TokenCustomizer<OAuth2TokenClaimsContext>} of the
 * server.
 */
@Component
@RequiredArgsConstructor
public class ReferenceTokenClaimsCustomizer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {

    /** The claims every issued token gets. */
    private final IssuedTokenClaims issuedTokenClaims;

    @Override
    public void customize(final OAuth2TokenClaimsContext context) {
        context.getClaims().claims(claims -> issuedTokenClaims.apply(context, claims));
    }
}
// end::tokens-reference-customizer[]
