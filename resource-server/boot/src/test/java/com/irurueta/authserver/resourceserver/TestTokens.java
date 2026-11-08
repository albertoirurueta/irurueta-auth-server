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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;

/**
 * Signs the JWTs the resource server integration tests present, with an RSA key generated when the class loads. The
 * public half is handed to the application through
 * {@code spring.security.oauth2.resourceserver.jwt.public-key-location}; Spring Boot only builds a decoder from that
 * key when {@code issuer-uri} is blank (otherwise it resolves the issuer's metadata over HTTP), so the tests blank it.
 * No key is ever committed.
 */
final class TestTokens {

    /** Lifetime of the test tokens. */
    static final Duration TOKEN_TTL = Duration.ofMinutes(5);

    /** Size in bits of the generated RSA key. */
    private static final int KEY_SIZE = 2048;

    /** Number of base64 characters per line of a PEM document. */
    private static final int PEM_LINE_LENGTH = 64;

    /** Key pair that signs the test tokens. */
    private static final KeyPair KEY_PAIR = generateKeyPair();

    /** Utility class, not meant to be instantiated. */
    private TestTokens() {
    }

    /**
     * Points the resource server's decoder at the public half of the generated key.
     *
     * @param registry registry of the test properties.
     * @throws IOException if the PEM file cannot be written.
     */
    static void publicKeyLocation(final DynamicPropertyRegistry registry) throws IOException {
        final var pem = Files.createTempFile("resource-server-test-key", ".pem");
        pem.toFile().deleteOnExit();
        Files.writeString(pem, toPem((RSAPublicKey) KEY_PAIR.getPublic()), StandardCharsets.US_ASCII);
        registry.add("spring.security.oauth2.resourceserver.jwt.public-key-location", () -> pem.toUri().toString());
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> "");
    }

    /**
     * Builds an {@code Authorization} header value carrying a token signed with the generated key.
     *
     * @param issuer    issuer claim of the token.
     * @param subject   subject claim of the token.
     * @param audiences audience claim of the token; empty to leave the claim out.
     * @param scope     space-separated scopes of the token; empty to leave the claim out.
     * @param roles     roles of the caller; empty to leave the claim out.
     * @param extra     further claims of the token.
     * @return the header value.
     */
    static String bearer(final String issuer, final String subject, final List<String> audiences, final String scope,
                         final List<String> roles, final Map<String, Object> extra) {
        return "Bearer " + tokenValue(issuer, subject, audiences, scope, roles, extra);
    }

    /**
     * Builds a token signed with the generated key, without any scheme prefix.
     *
     * @param issuer    issuer claim of the token.
     * @param subject   subject claim of the token.
     * @param audiences audience claim of the token; empty to leave the claim out.
     * @param scope     space-separated scopes of the token; empty to leave the claim out.
     * @param roles     roles of the caller; empty to leave the claim out.
     * @param extra     further claims of the token.
     * @return the compact token.
     */
    static String tokenValue(final String issuer, final String subject, final List<String> audiences,
                             final String scope, final List<String> roles, final Map<String, Object> extra) {
        final var rsaKey = new RSAKey.Builder((RSAPublicKey) KEY_PAIR.getPublic())
                .privateKey((RSAPrivateKey) KEY_PAIR.getPrivate())
                .build();
        final var encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(rsaKey)));
        final var now = Instant.now();
        final var claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(subject)
                .issuedAt(now)
                .expiresAt(now.plus(TOKEN_TTL));
        if (!audiences.isEmpty()) {
            claims.audience(audiences);
        }
        if (!scope.isEmpty()) {
            claims.claim("scope", scope);
        }
        if (!roles.isEmpty()) {
            claims.claim("roles", roles);
        }
        extra.forEach(claims::claim);
        return encoder.encode(JwtEncoderParameters.from(claims.build())).getTokenValue();
    }

    /**
     * Builds the {@code cnf} claim of a token bound to a TLS client certificate (RFC 8705).
     *
     * @param certificate the client certificate.
     * @return the extra claims to pass to {@link #tokenValue}.
     */
    static Map<String, Object> certificateBound(final X509Certificate certificate) {
        try {
            final var digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
            return Map.of("cnf", Map.of("x5t#S256", Base64.getUrlEncoder().withoutPadding().encodeToString(digest)));
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("Cannot compute the certificate thumbprint", e);
        }
    }

    /**
     * Generates an EC key pair for a DPoP client.
     *
     * @return the key, with its private half.
     */
    static ECKey dpopKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate();
        } catch (final JOSEException e) {
            throw new IllegalStateException("Cannot generate the DPoP key", e);
        }
    }

    /**
     * Builds the {@code cnf} claim of a token bound to a DPoP key (RFC 9449).
     *
     * @param key the DPoP key.
     * @return the extra claims to pass to {@link #tokenValue}.
     */
    static Map<String, Object> dpopBound(final ECKey key) {
        try {
            return Map.of("cnf", Map.of("jkt", key.computeThumbprint().toString()));
        } catch (final JOSEException e) {
            throw new IllegalStateException("Cannot compute the key thumbprint", e);
        }
    }

    /**
     * Builds a DPoP proof for a request.
     *
     * @param key         the DPoP key.
     * @param method      HTTP method of the request.
     * @param url         full URL of the request.
     * @param accessToken the access token the proof is bound to ({@code ath}).
     * @return the compact proof.
     */
    static String dpopProof(final ECKey key, final String method, final String url, final String accessToken) {
        try {
            final var hash = MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            final var claims = new JWTClaimsSet.Builder()
                    .jwtID(UUID.randomUUID().toString())
                    .claim("htm", method)
                    .claim("htu", url)
                    .claim("ath", Base64.getUrlEncoder().withoutPadding().encodeToString(hash))
                    .issueTime(new Date())
                    .build();
            final var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(key.toPublicJWK())
                    .build();
            final var jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (final GeneralSecurityException | JOSEException e) {
            throw new IllegalStateException("Cannot build the DPoP proof", e);
        }
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
