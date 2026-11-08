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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * Unit tests of {@link LegacyImplicitTokenGeneratorFactory}.
 */
@ExtendWith(MockitoExtension.class)
class LegacyImplicitTokenGeneratorFactoryTest {

    /** Signs the tokens. */
    @Mock
    private JwtEncoder jwtEncoder;

    /** Customizers of JWTs. */
    @Mock
    private ObjectProvider<OAuth2TokenCustomizer<JwtEncodingContext>> jwtCustomizers;

    /** Customizers of reference tokens. */
    @Mock
    private ObjectProvider<OAuth2TokenCustomizer<OAuth2TokenClaimsContext>> claimsCustomizers;


    /**
     * Verifies that the generator is built and asks for both kinds of customizer.
     */
    @Test
    void create_whenCalled_buildsTheGeneratorWithTheCustomizers() {
        final var factory = new LegacyImplicitTokenGeneratorFactory(jwtEncoder, jwtCustomizers, claimsCustomizers);

        assertNotNull(factory.create());

        verify(jwtCustomizers).ifAvailable(any());
        verify(claimsCustomizers).ifAvailable(any());
    }
}
