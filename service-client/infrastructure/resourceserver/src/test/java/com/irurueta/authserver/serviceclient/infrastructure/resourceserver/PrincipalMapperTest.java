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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.RSAPrivateKey;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * Unit tests of {@link PrincipalMapper}.
 */
class PrincipalMapperTest {

    /** Mapper under test. */
    private final PrincipalMapper mapper = new PrincipalMapper();

    /**
     * Verifies that the principal of the service client is named after the client.
     */
    @Test
    void serviceClient_whenCalled_isNamedAfterTheClient() {
        final var principal = mapper.serviceClient("my-client");

        assertEquals("my-client", principal.getName());
        assertTrue(principal.isAuthenticated());
    }

    /**
     * Verifies that a JWT's subject, plus a digest, names the principal, and that the token is the principal object.
     *
     * @throws Exception if the test JWT cannot be built.
     */
    @Test
    void user_whenTokenIsAJwt_isNamedAfterItsSubjectAndDigest() throws Exception {
        final var token = jwt("alice");

        final var principal = mapper.user(token);

        assertTrue(principal.getName().startsWith("alice#"));
        final var accessToken = assertInstanceOf(OAuth2AccessToken.class, principal.getPrincipal());
        assertEquals(token, accessToken.getTokenValue());
    }

    /**
     * Verifies that two different tokens of the same subject never share a name.
     *
     * @throws Exception if the test JWTs cannot be built.
     */
    @Test
    void user_whenTwoTokensShareTheSubject_namesDiffer() throws Exception {
        assertNotEquals(mapper.user(jwt("alice")).getName(), mapper.user(jwt("alice")).getName());
    }

    /**
     * Verifies that an opaque token still gets a name that depends on the token.
     */
    @Test
    void user_whenTokenIsOpaque_isNamedUserAndDigest() {
        final var principal = mapper.user("opaque-reference-token");

        assertTrue(principal.getName().startsWith("user#"));
        assertNotEquals(principal.getName(), mapper.user("another-opaque-token").getName());
    }

    /**
     * Builds a signed JWT.
     *
     * @param subject its {@code sub} claim.
     * @return the compact serialization.
     * @throws Exception if signing fails.
     */
    private static String jwt(final String subject) throws Exception {
        final var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256),
                new JWTClaimsSet.Builder().subject(subject).build());
        jwt.sign(new RSASSASigner((RSAPrivateKey) TestKeys.rsaKeyPair().getPrivate()));
        return jwt.serialize();
    }
}
