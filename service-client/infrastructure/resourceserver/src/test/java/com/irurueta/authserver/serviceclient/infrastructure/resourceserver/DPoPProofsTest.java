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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link DPoPProofs}.
 */
class DPoPProofsTest {

    /** URI of the request, with a query the proof must not state. */
    private static final URI URI_WITH_QUERY = URI.create("https://rs.example.com/api/documents?page=2");

    /** A token value. */
    private static final String TOKEN = "the-access-token";

    /**
     * Verifies that the proof of a token request binds the method and the URI without the query, and no token.
     *
     * @throws Exception if the proof cannot be built or parsed.
     */
    @Test
    void proof_whenThereIsNoToken_bindsMethodAndUriWithoutAth() throws Exception {
        final var claims = SignedJWT.parse(proofs().proof("POST", URI_WITH_QUERY)).getJWTClaimsSet();

        assertEquals("POST", claims.getStringClaim("htm"));
        assertEquals("https://rs.example.com/api/documents", claims.getStringClaim("htu"));
        assertNull(claims.getClaim("ath"));
        assertNotNull(claims.getJWTID());
    }

    /**
     * Verifies that the proof of a call with a token also binds the token's hash.
     *
     * @throws Exception if the proof cannot be built or parsed.
     */
    @Test
    void proof_whenThereIsAToken_bindsTheTokenHash() throws Exception {
        final var claims = SignedJWT.parse(proofs().proof("GET", URI_WITH_QUERY, TOKEN)).getJWTClaimsSet();
        final var digest = MessageDigest.getInstance("SHA-256").digest(TOKEN.getBytes(StandardCharsets.US_ASCII));

        assertEquals("GET", claims.getStringClaim("htm"));
        assertEquals(Base64URL.encode(digest).toString(), claims.getStringClaim("ath"));
    }

    /**
     * Verifies that a signing failure is reported as an illegal state.
     *
     * @throws Exception if the mock cannot be set up.
     */
    @Test
    void proof_whenSigningFails_throwsIllegalStateException() throws Exception {
        final var factory = mock(DPoPProofFactory.class);
        when(factory.createDPoPJWT(any(String.class), any(URI.class))).thenThrow(new JOSEException("no"));
        when(factory.createDPoPJWT(any(String.class), any(URI.class), any(DPoPAccessToken.class)))
                .thenThrow(new JOSEException("no"));
        final var proofs = new DPoPProofs(factory);

        assertThrows(IllegalStateException.class, () -> proofs.proof("POST", URI_WITH_QUERY));
        assertThrows(IllegalStateException.class, () -> proofs.proof("GET", URI_WITH_QUERY, TOKEN));
    }

    /**
     * Builds the proofs over a real factory and a key generated now.
     *
     * @return the proofs.
     * @throws JOSEException if the key cannot be generated.
     */
    private static DPoPProofs proofs() throws JOSEException {
        final var key = new ECKeyGenerator(Curve.P_256).generate();
        return new DPoPProofs(new DefaultDPoPProofFactory(key, JWSAlgorithm.ES256));
    }
}
