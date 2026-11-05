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

package com.irurueta.authserver.authorization.infrastructure.persistence.tokens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Integration tests of {@link ReuseDetectingAuthorizationService} over the JDBC authorization service and
 * PostgreSQL. No Spring context is needed.
 */
class ReuseDetectingAuthorizationServiceIT {

    /** Lifetime of access tokens, in seconds. */
    private static final long ACCESS_TTL_SECONDS = 60;

    /** Lifetime of refresh tokens, in seconds. */
    private static final long REFRESH_TTL_SECONDS = 3600;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Registered client every authorization belongs to. */
    private static RegisteredClient registeredClient;

    /** Service under test. */
    private static ReuseDetectingAuthorizationService service;

    /**
     * Connects to the migrated database, registers a client and builds the service.
     */
    @BeforeAll
    static void connect() {
        final var dataSource = MigratedPostgres.dataSource();
        jdbcClient = JdbcClient.create(dataSource);
        final var template = new JdbcTemplate(dataSource);
        final var clients = new JdbcRegisteredClientRepository(template);
        jdbcClient.sql("DELETE FROM oauth2_registered_client").update();
        registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-" + UUID.randomUUID())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).build();
        clients.save(registeredClient);
        service = new ReuseDetectingAuthorizationService(new JdbcOAuth2AuthorizationService(template, clients),
                jdbcClient);
    }

    /**
     * Removes the authorizations of the previous test; the consumed tokens cascade.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM oauth2_authorization").update();
    }

    /**
     * Verifies that rotating a refresh token records the old hash, that the new token keeps working, and that
     * presenting the old one revokes the authorization.
     */
    @Test
    void findByToken_whenRotatedTokenIsReplayed_revokesTheAuthorization() {
        final var now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        final var oldToken = refreshToken(now);
        final var original = authorization(oldToken, now);
        service.save(original);
        final var newToken = refreshToken(now);
        service.save(OAuth2Authorization.from(original).refreshToken(newToken).build());

        assertEquals(1, jdbcClient.sql("SELECT count(*) FROM consumed_refresh_tokens").query(Integer.class)
                .single());
        assertNotNull(service.findByToken(newToken.getTokenValue(), OAuth2TokenType.REFRESH_TOKEN));

        assertNull(service.findByToken(oldToken.getTokenValue(), OAuth2TokenType.REFRESH_TOKEN));

        assertNull(service.findById(original.getId()));
        assertNull(service.findByToken(newToken.getTokenValue(), OAuth2TokenType.REFRESH_TOKEN));
    }

    /**
     * Verifies that saving an authorization without rotating its refresh token records nothing.
     */
    @Test
    void save_whenRefreshTokenIsNotRotated_recordsNothing() {
        final var now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        final var original = authorization(refreshToken(now), now);
        service.save(original);

        service.save(original);

        assertEquals(0, jdbcClient.sql("SELECT count(*) FROM consumed_refresh_tokens").query(Integer.class)
                .single());
    }

    /**
     * Builds a refresh token with a random value.
     *
     * @param issuedAt issue instant.
     * @return the token.
     */
    private static OAuth2RefreshToken refreshToken(final Instant issuedAt) {
        return new OAuth2RefreshToken(UUID.randomUUID().toString(), issuedAt,
                issuedAt.plusSeconds(REFRESH_TTL_SECONDS));
    }

    /**
     * Builds an authorization holding an access token and the given refresh token.
     *
     * @param refreshToken its refresh token.
     * @param issuedAt     issue instant of the access token.
     * @return the authorization.
     */
    private static OAuth2Authorization authorization(final OAuth2RefreshToken refreshToken, final Instant issuedAt) {
        return OAuth2Authorization.withRegisteredClient(registeredClient).id(UUID.randomUUID().toString())
                .principalName("alice").authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, UUID.randomUUID().toString(),
                        issuedAt, issuedAt.plusSeconds(ACCESS_TTL_SECONDS)))
                .refreshToken(refreshToken).build();
    }
}
