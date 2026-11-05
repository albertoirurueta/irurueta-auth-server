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
package com.irurueta.authserver.authorization;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.ApiSecurityConfig;
import com.irurueta.authserver.authorization.domain.account.SignedTokenService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Checks the API security chain in a web slice with a probe controller, with tokens signed by a key generated for
 * the test run and published through a real in-memory {@link JWKSource} (test data, not a double of a port of this
 * repository). It is an integration test because it starts a Spring context.
 */
@WebMvcTest(controllers = ApiSecurityConfigIT.ProbeController.class)
@Import({ApiSecurityConfig.class, ApiSecurityConfigIT.ProbeController.class, ApiSecurityConfigIT.TestKeys.class})
@TestPropertySource(properties = {
        "spring.security.oauth2.authorizationserver.issuer=" + ApiSecurityConfigIT.ISSUER,
        ApiSecurityConfig.API_AUDIENCE_PROPERTY + "=" + ApiSecurityConfigIT.API_AUDIENCE})
class ApiSecurityConfigIT {

    /** Issuer of the server under test. */
    static final String ISSUER = "http://issuer.test";

    /** Audience the API requires. */
    static final String API_AUDIENCE = "auth-server";

    /** Path of a protected endpoint. */
    private static final String PROTECTED_PATH = "/api/probe";

    /** Path of an administration endpoint. */
    private static final String ADMIN_PATH = "/api/admin/probe";

    /** Name of the request header that carries the bearer token. */
    private static final String AUTHORIZATION = "Authorization";

    /** Name of the response header that carries the bearer challenge. */
    private static final String CHALLENGE = "WWW-Authenticate";

    /** Error code of RFC 6750 for a rejected token. */
    private static final String INVALID_TOKEN = "invalid_token";

    /** Size in bits of the generated RSA key. */
    private static final int KEY_SIZE = 2048;

    /** Lifetime of the test tokens. */
    private static final Duration TOKEN_TTL = Duration.ofMinutes(5);

    /** Key generated for the test run; signs the tokens and is published to the chain. */
    private static final RSAKey KEY = generateKey();

    /** MockMvc bound to the web slice. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that a request without token is rejected with a bearer challenge.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenNoToken_returns401WithBearerChallenge() throws Exception {
        mockMvc.perform(get(PROTECTED_PATH))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(CHALLENGE, startsWith("Bearer")));
    }

    /**
     * Verifies that a malformed token is rejected with the {@code invalid_token} error of RFC 6750.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenTokenIsMalformed_returns401InvalidToken() throws Exception {
        mockMvc.perform(get(PROTECTED_PATH).header(AUTHORIZATION, "Bearer bad"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(CHALLENGE, containsString(INVALID_TOKEN)));
    }

    /**
     * Verifies that a token signed by this server, for its issuer and the API audience, reaches the endpoint.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenTokenIsForTheApiAudience_isAllowed() throws Exception {
        mockMvc.perform(get(PROTECTED_PATH).header(AUTHORIZATION, bearer(claims -> { })))
                .andExpect(status().isOk());
    }

    /**
     * Verifies that a token issued for the resource server only (a user's access token for another API) is
     * rejected, although this server signed it.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenTokenIsForTheResourceServerOnly_returns401InvalidToken() throws Exception {
        mockMvc.perform(get(PROTECTED_PATH)
                        .header(AUTHORIZATION, bearer(claims -> claims.audience(List.of("resource-server")))))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(CHALLENGE, containsString(INVALID_TOKEN)));
    }

    /**
     * Verifies that a token without any audience is rejected.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenTokenHasNoAudience_returns401InvalidToken() throws Exception {
        mockMvc.perform(get(PROTECTED_PATH)
                        .header(AUTHORIZATION, bearer(claims -> claims.claims(all -> all.remove("aud")))))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(CHALLENGE, containsString(INVALID_TOKEN)));
    }

    /**
     * Verifies that an e-mail verification JWT (it carries the {@code purpose} claim) is never accepted as a bearer
     * token, even when it would otherwise pass every check.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenTokenIsAVerificationToken_returns401InvalidToken() throws Exception {
        mockMvc.perform(get(PROTECTED_PATH).header(AUTHORIZATION,
                        bearer(claims -> claims.claim(SignedTokenService.PURPOSE_CLAIM, "email_verification"))))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(CHALLENGE, containsString(INVALID_TOKEN)));
    }

    /**
     * Verifies that a token from another issuer is rejected.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenIssuerIsOther_returns401InvalidToken() throws Exception {
        mockMvc.perform(get(PROTECTED_PATH).header(AUTHORIZATION, bearer(claims -> claims.issuer("http://other"))))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(CHALLENGE, containsString(INVALID_TOKEN)));
    }

    /**
     * Verifies that an expired token is rejected.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenTokenIsExpired_returns401InvalidToken() throws Exception {
        final var past = Instant.now().minus(Duration.ofHours(1));
        mockMvc.perform(get(PROTECTED_PATH).header(AUTHORIZATION,
                        bearer(claims -> claims.issuedAt(past.minus(TOKEN_TTL)).expiresAt(past))))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(CHALLENGE, containsString(INVALID_TOKEN)));
    }

    /**
     * Verifies that a state-changing request needs no CSRF token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenPostedWithoutCsrf_isAllowed() throws Exception {
        mockMvc.perform(post(PROTECTED_PATH).with(jwt()))
                .andExpect(status().isOk());
    }

    /**
     * Verifies that the API does not create a session.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenTokenIsValid_createsNoSession() throws Exception {
        final var session = mockMvc.perform(get(PROTECTED_PATH).with(jwt()))
                .andReturn().getRequest().getSession(false);

        assertNull(session);
    }

    /**
     * Verifies that the public account endpoints need no token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void publicEndpoints_whenNoToken_areNotChallenged() throws Exception {
        mockMvc.perform(post("/api/account/register")).andExpect(status().isOk());
        mockMvc.perform(post("/api/account/password/reset")).andExpect(status().isOk());
        mockMvc.perform(get("/api/account/verify")).andExpect(status().isOk());
    }

    /**
     * Verifies that registration is public only for the documented method.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void register_whenMethodIsGetAndNoToken_returns401() throws Exception {
        mockMvc.perform(get("/api/account/register")).andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that an administration endpoint accepts a real token with the {@code admin} scope.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void adminEndpoint_whenTokenHasAdminScope_isAllowed() throws Exception {
        mockMvc.perform(get(ADMIN_PATH).header(AUTHORIZATION, bearer(claims -> claims.claim("scope", "admin"))))
                .andExpect(status().isOk());
    }

    /**
     * Verifies that the {@code ADMIN} role alone no longer opens the administration API: a real token whose
     * {@code roles} claim (converted by the chain's own converter) holds {@code ROLE_ADMIN}, without the
     * {@code admin} scope, is forbidden with {@code insufficient_scope}.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void adminEndpoint_whenTokenHasAdminRoleWithoutAdminScope_returns403() throws Exception {
        mockMvc.perform(get(ADMIN_PATH).header(AUTHORIZATION, bearer(claims -> claims
                        .claim("roles", List.of("ROLE_ADMIN")).claim("scope", "openid profile"))))
                .andExpect(status().isForbidden())
                .andExpect(header().string(CHALLENGE, containsString("insufficient_scope")));
    }

    /**
     * Verifies that an administration endpoint rejects a token without the scope, with the
     * {@code insufficient_scope} error of RFC 6750.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void adminEndpoint_whenTokenLacksAdminAuthority_returns403() throws Exception {
        mockMvc.perform(get(ADMIN_PATH).with(jwt().jwt(token -> token.claim("scope", "read"))))
                .andExpect(status().isForbidden())
                .andExpect(header().string(CHALLENGE, containsString("insufficient_scope")));
    }

    /**
     * Builds an {@code Authorization} header value carrying a token signed with the test key: issued by
     * {@link #ISSUER} for {@link #API_AUDIENCE}, valid now, and adjusted by the given customizer.
     *
     * @param customizer changes to the default claims.
     * @return the header value.
     */
    private static String bearer(final Consumer<JwtClaimsSet.Builder> customizer) {
        final var now = Instant.now();
        final var claims = JwtClaimsSet.builder()
                .issuer(ISSUER)
                .subject("user-" + UUID.randomUUID())
                .audience(List.of(API_AUDIENCE))
                .issuedAt(now)
                .expiresAt(now.plus(TOKEN_TTL));
        customizer.accept(claims);
        final var encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(KEY)));
        return "Bearer " + encoder.encode(JwtEncoderParameters.from(claims.build())).getTokenValue();
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
                    .privateKey((RSAPrivateKey) pair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA is not available", e);
        }
    }

    /**
     * Probe endpoints that stand in for the real API. Package-private: the class-level {@code @Import} names it.
     */
    @RestController
    @RequestMapping("/api")
    static class ProbeController {

        /**
         * Answers any request of the probe endpoints.
         *
         * @return an empty body.
         */
        @RequestMapping({"/probe", "/admin/probe", "/account/verify", "/account/register", "/account/password/reset"})
        String probe() {
            return "ok";
        }
    }

    /**
     * Publishes the public half of the test key, as the application publishes its signing keys. Package-private:
     * the class-level {@code @Import} names it, and Spring only detects non-private nested configuration classes.
     */
    @TestConfiguration(proxyBeanMethods = false)
    static class TestKeys {

        /**
         * Creates the published key set.
         *
         * @return the source of the public test key.
         */
        @Bean
        JWKSource<SecurityContext> jwkSource() {
            return new ImmutableJWKSet<>(new JWKSet(KEY.toPublicJWK()));
        }
    }
}
