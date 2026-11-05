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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;

import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

/**
 * Unit tests of {@link RolesTenantAudienceTokenCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class RolesTenantAudienceTokenCustomizerTest {

    /** Name of the claim the mocked claims add. */
    private static final String CLAIM = "tenant";

    /** The claims every issued token gets. */
    @Mock
    private IssuedTokenClaims issuedTokenClaims;

    /** Subject under test. */
    @InjectMocks
    private RolesTenantAudienceTokenCustomizer customizer;

    /**
     * Verifies that the customizer applies the issued-token claims to the claims of the JWT being encoded.
     */
    @Test
    void customize_whenCalled_appliesTheIssuedTokenClaimsToTheJwt() {
        final var client = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("client")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();
        final var context = JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256),
                        JwtClaimsSet.builder().subject("client"))
                .registeredClient(client).principal(new TestingAuthenticationToken("client", null))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        doAnswer(invocation -> invocation.<Map<String, Object>>getArgument(1).put(CLAIM, "acme"))
                .when(issuedTokenClaims).apply(eq(context), anyMap());

        customizer.customize(context);

        assertEquals("acme", context.getClaims().build().getClaim(CLAIM));
    }
}
