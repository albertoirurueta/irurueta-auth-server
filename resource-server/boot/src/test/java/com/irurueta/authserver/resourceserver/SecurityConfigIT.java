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

package com.irurueta.authserver.resourceserver;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration tests of {@link com.irurueta.authserver.resourceserver.api.web.security.SecurityConfig} through the
 * whole filter chain, against the test-only {@link ProtectedTestController}.
 *
 * <p>The real-token tests sign JWTs with an RSA key generated here and point
 * {@code spring.security.oauth2.resourceserver.jwt.public-key-location} at its public half. Spring Boot only builds
 * a decoder from that key when {@code issuer-uri} is blank (otherwise it resolves the issuer's metadata over HTTP),
 * so the tests blank it. The configured audiences still apply: the audience validator the application really uses
 * is exercised without starting the authorization server. No key is ever committed.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigIT {

    /** Subject of the test bearer token. */
    private static final String SUBJECT = "demo";

    /** Issuer claim of the test tokens. */
    private static final String ISSUER = "http://localhost:9000";

    /** Audience the resource server accepts by default. */
    private static final String ACCEPTED_AUDIENCE = "bff";

    /** Audience of a token issued to another client. */
    private static final String OTHER_AUDIENCE = "service-client";

    /** Size in bits of the generated RSA key. */
    private static final int KEY_SIZE = 2048;

    /** Number of base64 characters per line of a PEM document. */
    private static final int PEM_LINE_LENGTH = 64;

    /** Lifetime of the test tokens. */
    private static final Duration TOKEN_TTL = Duration.ofMinutes(5);

    /** Key pair that signs the test tokens. */
    private static final KeyPair KEY_PAIR = generateKeyPair();

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Points the resource server's decoder at the public half of the generated key.
     *
     * @param registry registry of the test properties.
     * @throws IOException if the PEM file cannot be written.
     */
    @DynamicPropertySource
    static void publicKeyLocation(final DynamicPropertyRegistry registry) throws IOException {
        final var pem = Files.createTempFile("resource-server-test-key", ".pem");
        pem.toFile().deleteOnExit();
        Files.writeString(pem, toPem((RSAPublicKey) KEY_PAIR.getPublic()), StandardCharsets.US_ASCII);
        registry.add("spring.security.oauth2.resourceserver.jwt.public-key-location", () -> pem.toUri().toString());
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> "");
    }

    /**
     * Verifies that a request without a bearer token is rejected.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenThereIsNoToken_returnsUnauthorized() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH)).andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that an authenticated request reaches the endpoint with the token's claims.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenTokenIsValid_exposesTheTokenToTheEndpoint() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH).with(jwt().jwt(token -> token.subject(SUBJECT))))
                .andExpect(status().isOk())
                .andExpect(content().string(SUBJECT));
    }

    /**
     * Verifies that a signed token issued to the accepted audience passes the real decoder.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenTokenAudienceIsAccepted_returnsOk() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH)
                        .header(HttpHeaders.AUTHORIZATION, bearer(ISSUER, List.of(ACCEPTED_AUDIENCE))))
                .andExpect(status().isOk())
                .andExpect(content().string(SUBJECT));
    }

    /**
     * Verifies that a signed token issued to another client is rejected by the audience validator.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenTokenAudienceIsOther_returnsUnauthorized() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH)
                        .header(HttpHeaders.AUTHORIZATION, bearer(ISSUER, List.of(OTHER_AUDIENCE))))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that a signed token without any audience is rejected.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenTokenHasNoAudience_returnsUnauthorized() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH)
                        .header(HttpHeaders.AUTHORIZATION, bearer(ISSUER, List.of())))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Builds an {@code Authorization} header value carrying a token signed with the generated key.
     *
     * @param issuer    issuer claim of the token.
     * @param audiences audience claim of the token; empty to leave the claim out.
     * @return the header value.
     */
    private static String bearer(final String issuer, final List<String> audiences) {
        final var rsaKey = new RSAKey.Builder((RSAPublicKey) KEY_PAIR.getPublic())
                .privateKey((RSAPrivateKey) KEY_PAIR.getPrivate())
                .build();
        final var encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(rsaKey)));
        final var now = Instant.now();
        final var claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(SUBJECT)
                .issuedAt(now)
                .expiresAt(now.plus(TOKEN_TTL));
        if (!audiences.isEmpty()) {
            claims.audience(audiences);
        }
        return "Bearer " + encoder.encode(JwtEncoderParameters.from(claims.build())).getTokenValue();
    }

    /**
     * Encodes a public key as a PEM document with {@code \n} line endings.
     *
     * @param key the public key.
     * @return the PEM document.
     */
    private static String toPem(final RSAPublicKey key) {
        final var encoder = Base64.getMimeEncoder(PEM_LINE_LENGTH, "\n".getBytes(StandardCharsets.US_ASCII));
        return "-----BEGIN PUBLIC KEY-----\n" + encoder.encodeToString(key.getEncoded())
                + "\n-----END PUBLIC KEY-----\n";
    }

    /**
     * Generates the RSA key pair that signs the test tokens.
     *
     * @return the key pair.
     */
    private static KeyPair generateKeyPair() {
        try {
            final var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_SIZE);
            return generator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA is not available", e);
        }
    }
}
