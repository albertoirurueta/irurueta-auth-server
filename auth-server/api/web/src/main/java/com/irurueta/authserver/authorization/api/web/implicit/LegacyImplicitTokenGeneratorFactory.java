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
package com.irurueta.authserver.authorization.api.web.implicit;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * Builds the token generator of the legacy flow with the claims customizers of the server, so its tokens carry the same
 * roles, tenant, audience and authentication claims as those of the other flows. The generator is deliberately not a
 * bean: a bean of that type would replace the one the framework builds for every other flow.
 */
@RequiredArgsConstructor
public class LegacyImplicitTokenGeneratorFactory {

    /** Signs the self-contained tokens. */
    private final JwtEncoder jwtEncoder;

    /** Adds the claims of the server to a JWT. */
    private final ObjectProvider<OAuth2TokenCustomizer<JwtEncodingContext>> jwtCustomizers;

    /** Adds the claims of the server to a reference token. */
    private final ObjectProvider<OAuth2TokenCustomizer<OAuth2TokenClaimsContext>> claimsCustomizers;

    /**
     * Creates the generator: a JWT for a client of self-contained tokens, an opaque token otherwise.
     *
     * @return the generator.
     */
    public OAuth2TokenGenerator<OAuth2Token> create() {
        final var jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtCustomizers.ifAvailable(jwtGenerator::setJwtCustomizer);
        final var accessTokenGenerator = new OAuth2AccessTokenGenerator();
        claimsCustomizers.ifAvailable(accessTokenGenerator::setAccessTokenCustomizer);
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator);
    }
}
