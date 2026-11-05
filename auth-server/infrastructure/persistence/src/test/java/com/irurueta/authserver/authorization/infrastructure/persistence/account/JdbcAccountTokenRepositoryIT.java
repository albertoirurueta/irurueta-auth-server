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

package com.irurueta.authserver.authorization.infrastructure.persistence.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.account.AccountToken;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcAccountTokenRepository} against PostgreSQL. No Spring context is needed.
 */
class JdbcAccountTokenRepositoryIT {

    /** Purpose used by the tests. */
    private static final String PURPOSE = AccountToken.PURPOSE_EMAIL_VERIFICATION;

    /** Lifetime of the tokens, in seconds. */
    private static final long TTL_SECONDS = 60;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcAccountTokenRepository repository;

    /** Identifier of the user that owns the tokens. */
    private UUID userId;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcAccountTokenRepository(jdbcClient, new AccountTokenRowMapper());
    }

    /**
     * Removes the data of the previous test and inserts the user that owns the tokens.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
        userId = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(userId, "user-" + userId).update();
    }

    /**
     * Verifies that an unused, unexpired token is consumed once and cannot be consumed again.
     */
    @Test
    void consume_whenTokenIsValid_returnsItOnlyOnce() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        final var hash = hash();
        repository.store(token(hash, now.plusSeconds(TTL_SECONDS)));

        final var first = repository.consume(hash, PURPOSE, now).orElseThrow();
        final var second = repository.consume(hash, PURPOSE, now);

        assertEquals(hash, first.hashedToken());
        assertEquals(now, first.usedAt());
        assertTrue(second.isEmpty());
    }

    /**
     * Verifies that an expired token is not consumed.
     */
    @Test
    void consume_whenTokenIsExpired_returnsEmpty() {
        final var now = Instant.now();
        final var hash = hash();
        repository.store(token(hash, now.minusSeconds(1)));

        assertTrue(repository.consume(hash, PURPOSE, now).isEmpty());
    }

    /**
     * Verifies that a token is not consumed for another purpose.
     */
    @Test
    void consume_whenPurposeDiffers_returnsEmpty() {
        final var now = Instant.now();
        final var hash = hash();
        repository.store(token(hash, now.plusSeconds(TTL_SECONDS)));

        assertTrue(repository.consume(hash, AccountToken.PURPOSE_PASSWORD_RESET, now).isEmpty());
    }

    /**
     * Verifies that a usable token is found without being consumed, so it can still be consumed afterwards, and
     * that a consumed, expired or other-purpose token is not found.
     */
    @Test
    void findUsable_whenTokenIsUsable_findsItWithoutConsumingIt() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        final var hash = hash();
        repository.store(token(hash, now.plusSeconds(TTL_SECONDS)));
        final var expired = hash();
        repository.store(token(expired, now.minusSeconds(1)));

        assertTrue(repository.findUsable(hash, PURPOSE, now).isPresent());
        assertTrue(repository.findUsable(hash, PURPOSE, now).isPresent());
        assertTrue(repository.findUsable(hash, AccountToken.PURPOSE_PASSWORD_RESET, now).isEmpty());
        assertTrue(repository.findUsable(expired, PURPOSE, now).isEmpty());
        assertTrue(repository.consume(hash, PURPOSE, now).isPresent());
        assertTrue(repository.findUsable(hash, PURPOSE, now).isEmpty());
    }

    /**
     * Verifies that only the expired tokens are deleted.
     */
    @Test
    void deleteExpired_whenSomeTokensExpired_deletesOnlyThose() {
        final var now = Instant.now();
        repository.store(token(hash(), now.minusSeconds(1)));
        repository.store(token(hash(), now.plusSeconds(TTL_SECONDS)));

        assertEquals(1, repository.deleteExpired(now));
    }

    /**
     * Builds an unused token of the user.
     *
     * @param hash      hash of the token.
     * @param expiresAt expiry instant.
     * @return the token.
     */
    private AccountToken token(final String hash, final Instant expiresAt) {
        return new AccountToken(UUID.randomUUID(), userId, PURPOSE, hash, expiresAt, null);
    }

    /**
     * Generates a random token hash.
     *
     * @return the hash placeholder.
     */
    private static String hash() {
        return "hash-" + UUID.randomUUID();
    }
}
