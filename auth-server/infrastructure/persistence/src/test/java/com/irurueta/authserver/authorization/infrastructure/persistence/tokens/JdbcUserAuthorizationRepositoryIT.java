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
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Integration tests of {@link JdbcUserAuthorizationRepository} against PostgreSQL. No Spring context is needed.
 */
class JdbcUserAuthorizationRepositoryIT {

    /** Seconds in a minute. */
    private static final long ONE_MINUTE = 60;

    /** Seconds in two minutes. */
    private static final long TWO_MINUTES = 120;

    /** Seconds in half a minute. */
    private static final long HALF_MINUTE = 30;

    /** Seconds in an hour. */
    private static final long ONE_HOUR = 3600;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Service that stores the authorizations the tests clean up. */
    private static JdbcOAuth2AuthorizationService authorizationService;

    /** Registered client every authorization belongs to. */
    private static RegisteredClient registeredClient;

    /** Repository under test. */
    private static JdbcUserAuthorizationRepository repository;

    /**
     * Connects to the migrated database, registers a client and builds the repository.
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
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();
        clients.save(registeredClient);
        authorizationService = new JdbcOAuth2AuthorizationService(template, clients);
        repository = new JdbcUserAuthorizationRepository(jdbcClient);
    }

    /**
     * Removes the authorizations of the previous test.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM oauth2_authorization").update();
    }

    /**
     * Verifies that only the authorizations of the principal are deleted.
     */
    @Test
    void deleteByPrincipalName_whenPrincipalHasAuthorizations_deletesOnlyTheirs() {
        final var now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        final var expires = now.plusSeconds(ONE_MINUTE);
        authorizationService.save(authorization("alice", now, expires, expires));
        authorizationService.save(authorization("bob", now, now.plusSeconds(ONE_MINUTE), now.plusSeconds(ONE_MINUTE)));

        assertEquals(1, repository.deleteByPrincipalName("alice"));
        assertEquals(1, jdbcClient.sql("SELECT count(*) FROM oauth2_authorization").query(Integer.class).single());
    }

    /**
     * Verifies that an authorization is deleted only when all its tokens have expired, covering the refresh token
     * column too.
     */
    @Test
    void deleteExpired_whenOnlyTheAccessTokenExpired_keepsTheAuthorization() {
        final var now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        authorizationService.save(authorization("alice", now.minusSeconds(TWO_MINUTES), now.minusSeconds(ONE_MINUTE),
                now.plusSeconds(ONE_HOUR)));
        authorizationService.save(authorization("bob", now.minusSeconds(TWO_MINUTES), now.minusSeconds(ONE_MINUTE),
                now.minusSeconds(HALF_MINUTE)));

        assertEquals(1, repository.deleteExpired(now));
        assertEquals(1, jdbcClient.sql("SELECT count(*) FROM oauth2_authorization WHERE principal_name = 'alice'")
                .query(Integer.class).single());
    }

    /**
     * Builds an authorization with an access token and a refresh token.
     *
     * @param principal      principal of the authorization.
     * @param issuedAt       issue instant of the tokens.
     * @param accessExpires  expiry of the access token.
     * @param refreshExpires expiry of the refresh token.
     * @return the authorization.
     */
    private static OAuth2Authorization authorization(
            final String principal, final Instant issuedAt, final Instant accessExpires,
            final Instant refreshExpires) {
        return OAuth2Authorization.withRegisteredClient(registeredClient).id(UUID.randomUUID().toString())
                .principalName(principal).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, UUID.randomUUID().toString(),
                        issuedAt, accessExpires))
                .refreshToken(new OAuth2RefreshToken(UUID.randomUUID().toString(), issuedAt, refreshExpires))
                .build();
    }
}
