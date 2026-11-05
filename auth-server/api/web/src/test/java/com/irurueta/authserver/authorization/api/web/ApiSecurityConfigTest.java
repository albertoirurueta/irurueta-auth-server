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
package com.irurueta.authserver.authorization.api.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.irurueta.authserver.authorization.domain.account.SignedTokenService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * Unit tests of the token converter and the token decoder of {@link ApiSecurityConfig}, with a key generated for the
 * test run.
 */
class ApiSecurityConfigTest {

    /** Lifetime in seconds of the test tokens. */
    private static final long TTL_SECONDS = 60;

    /** Issuer the decoder requires. */
    private static final String ISSUER = "http://issuer.test";

    /** Audience the decoder requires. */
    private static final String AUDIENCE = "auth-server";

    /** Size in bits of the generated RSA key. */
    private static final int KEY_SIZE = 2048;

    /** Key generated for the test run. */
    private static final RSAKey KEY = generateKey();

    /** Decoder under test, trusting the public half of the key. */
    private static final JwtDecoder DECODER = ApiSecurityConfig.apiJwtDecoder(
            new ImmutableJWKSet<>(new JWKSet(KEY.toPublicJWK())), ISSUER, AUDIENCE);

    /**
     * Verifies that a token signed with the published key, for the issuer and the audience, is decoded.
     */
    @Test
    void apiJwtDecoder_whenTokenIsForTheApi_decodesIt() {
        final var jwt = DECODER.decode(sign(claims -> { }));

        assertEquals(List.of(AUDIENCE), jwt.getAudience());
    }

    /**
     * Verifies that a token for another audience only is rejected.
     */
    @Test
    void apiJwtDecoder_whenAudienceIsOther_throwsJwtValidationException() {
        final var token = sign(claims -> claims.audience(List.of("resource-server")));

        assertThrows(JwtValidationException.class, () -> DECODER.decode(token));
    }

    /**
     * Verifies that a token carrying the {@code purpose} claim of the account tokens is rejected.
     */
    @Test
    void apiJwtDecoder_whenTokenHasAPurpose_throwsJwtValidationException() {
        final var token = sign(claims -> claims.claim(SignedTokenService.PURPOSE_CLAIM, "email_verification"));

        assertThrows(JwtValidationException.class, () -> DECODER.decode(token));
    }

    /**
     * Verifies that a token from another issuer is rejected.
     */
    @Test
    void apiJwtDecoder_whenIssuerIsOther_throwsJwtValidationException() {
        final var token = sign(claims -> claims.issuer("http://other.test"));

        assertThrows(JwtValidationException.class, () -> DECODER.decode(token));
    }

    /**
     * Verifies that scopes become {@code SCOPE_*} authorities.
     */
    @Test
    void apiJwtAuthenticationConverter_whenTokenHasScopes_mapsThemToScopeAuthorities() {
        final var authorities = convert(Jwt.withTokenValue("t").header("alg", "none")
                .claim("scope", "read admin").issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(TTL_SECONDS)).build());

        assertEquals(Set.of("SCOPE_read", "SCOPE_admin"), authorities);
    }

    /**
     * Verifies that roles become {@code ROLE_*} authorities, without doubling an existing prefix.
     */
    @Test
    void apiJwtAuthenticationConverter_whenTokenHasRoles_mapsThemToRoleAuthorities() {
        final var authorities = convert(Jwt.withTokenValue("t").header("alg", "none")
                .claim("roles", List.of("USER", "ROLE_ADMIN")).issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(TTL_SECONDS)).build());

        assertEquals(Set.of("ROLE_USER", "ROLE_ADMIN"), authorities);
    }

    /**
     * Verifies that a token without scopes and roles has no authorities.
     */
    @Test
    void apiJwtAuthenticationConverter_whenTokenHasNoScopesNorRoles_hasNoAuthorities() {
        final var authorities = convert(Jwt.withTokenValue("t").header("alg", "none").claim("sub", "u")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(TTL_SECONDS)).build());

        assertEquals(Set.of(), authorities);
    }

    /**
     * Converts a token and returns the names of its scope and role authorities; the framework's own
     * {@code FACTOR_*} authority, which records how the caller authenticated, is left out.
     *
     * @param jwt token to convert.
     * @return authority names.
     */
    private static Set<String> convert(final Jwt jwt) {
        final var converter = new ApiSecurityConfig().apiJwtAuthenticationConverter();
        final var authentication = converter.convert(jwt);
        assertNotNull(authentication);
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(name -> !name.startsWith("FACTOR_"))
                .collect(Collectors.toSet());
    }

    /**
     * Signs a token with the test key: issued by {@link #ISSUER} for {@link #AUDIENCE}, valid now, and adjusted by
     * the given customizer.
     *
     * @param customizer changes to the default claims.
     * @return the compact token.
     */
    private static String sign(final Consumer<JwtClaimsSet.Builder> customizer) {
        final var now = Instant.now();
        final var claims = JwtClaimsSet.builder().issuer(ISSUER).subject("user").audience(List.of(AUDIENCE))
                .issuedAt(now).expiresAt(now.plusSeconds(TTL_SECONDS));
        customizer.accept(claims);
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(KEY)))
                .encode(JwtEncoderParameters.from(claims.build())).getTokenValue();
    }

    /**
     * Generates the RSA key of the test run.
     *
     * @return the key, with its private half.
     */
    private static RSAKey generateKey() {
        try {
            final var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_SIZE);
            final var pair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                    .privateKey((RSAPrivateKey) pair.getPrivate()).keyID(UUID.randomUUID().toString()).build();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA is not available", e);
        }
    }
}
