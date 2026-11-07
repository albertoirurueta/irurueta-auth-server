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

package com.irurueta.authserver.authorization.infrastructure.persistence.sms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerification;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcPhoneVerificationRepository} against PostgreSQL with the real migrations.
 */
class JdbcPhoneVerificationRepositoryIT {

    /** Pending phone number. */
    private static final PhoneNumber PENDING = new PhoneNumber("+34600000021");

    /** Verified phone number. */
    private static final PhoneNumber VERIFIED = new PhoneNumber("+34600000022");

    /** Instant used by the tests, truncated to what the database stores. */
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.MILLIS);

    /** Expiry instant of a verification that has not expired. */
    private static final Instant FUTURE = NOW.plus(Duration.ofMinutes(1));

    /** Number of concurrent threads in the atomicity test. */
    private static final int THREADS = 8;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcPhoneVerificationRepository repository;

    /** Repository of the verified phones. */
    private static JdbcUserPhoneRepository phones;

    /** User of the verification. */
    private UUID userId;

    /**
     * Connects to the migrated database and builds the repositories.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcPhoneVerificationRepository(jdbcClient, new PhoneVerificationRowMapper());
        phones = new JdbcUserPhoneRepository(jdbcClient, new UserPhoneRowMapper());
    }

    /**
     * Removes the data of the previous test and inserts a user.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
        userId = insertUser();
    }

    /**
     * Verifies that a saved verification is found and that a second save replaces it.
     */
    @Test
    void save_whenCalledTwice_replacesVerification() {
        repository.save(verification(userId, FUTURE));
        final var replacement = new PhoneVerification(userId, VERIFIED, "other", 0, FUTURE.plusSeconds(1));

        repository.save(replacement);

        assertEquals(replacement, repository.findByUserId(userId).orElseThrow());
    }

    /**
     * Verifies that a user without a pending verification has none, even with a verified phone.
     */
    @Test
    void findByUserId_whenNothingIsPending_returnsEmpty() {
        assertTrue(repository.findByUserId(userId).isEmpty());
        phones.save(new UserPhone(userId, VERIFIED, NOW));

        assertTrue(repository.findByUserId(userId).isEmpty());
    }

    /**
     * Verifies that saving a verification keeps the verified phone.
     */
    @Test
    void save_whenPhoneIsVerified_keepsVerifiedPhone() {
        final var phone = new UserPhone(userId, VERIFIED, NOW);
        phones.save(phone);

        repository.save(verification(userId, FUTURE));

        assertEquals(phone, phones.findByUserId(userId).orElseThrow());
    }

    /**
     * Verifies that attempts are counted and an absent verification reports zero.
     */
    @Test
    void incrementAttempts_whenCalled_countsAttempts() {
        assertEquals(0, repository.incrementAttempts(userId));
        repository.save(verification(userId, FUTURE));

        assertEquals(1, repository.incrementAttempts(userId));
        assertEquals(2, repository.incrementAttempts(userId));
        assertEquals(2, repository.findByUserId(userId).orElseThrow().attempts());
    }

    /**
     * Verifies that concurrent increments never lose an update.
     *
     * @throws Exception if a worker fails.
     */
    @Test
    void incrementAttempts_whenConcurrent_neverLosesAnIncrement() throws Exception {
        repository.save(verification(userId, FUTURE));
        final var executor = Executors.newFixedThreadPool(THREADS);
        try {
            final var futures = IntStream.range(0, THREADS)
                    .mapToObj(i -> executor.submit(() -> repository.incrementAttempts(userId))).toList();
            for (final var future : futures) {
                future.get();
            }
        } finally {
            executor.shutdownNow();
        }

        assertEquals(THREADS, repository.findByUserId(userId).orElseThrow().attempts());
    }

    /**
     * Verifies that deleting removes the row when no verified phone remains.
     */
    @Test
    void deleteByUserId_whenNoVerifiedPhone_removesRow() {
        repository.save(verification(userId, FUTURE));

        repository.deleteByUserId(userId);

        assertTrue(repository.findByUserId(userId).isEmpty());
        assertEquals(0, jdbcClient.sql("SELECT count(*) FROM user_phones WHERE user_id = ?").param(userId)
                .query(Integer.class).single());
    }

    /**
     * Verifies that deleting keeps the verified phone.
     */
    @Test
    void deleteByUserId_whenPhoneIsVerified_keepsVerifiedPhone() {
        final var phone = new UserPhone(userId, VERIFIED, NOW);
        phones.save(phone);
        repository.save(verification(userId, FUTURE));

        repository.deleteByUserId(userId);

        assertTrue(repository.findByUserId(userId).isEmpty());
        assertEquals(phone, phones.findByUserId(userId).orElseThrow());
    }

    /**
     * Verifies that only expired verifications are cleared and their empty rows removed.
     */
    @Test
    void deleteExpired_whenSomeAreExpired_clearsOnlyThose() {
        final var otherUser = insertUser();
        final var verifiedUser = insertUser();
        repository.save(verification(userId, NOW.minusSeconds(1)));
        repository.save(verification(otherUser, FUTURE));
        phones.save(new UserPhone(verifiedUser, VERIFIED, NOW));
        repository.save(new PhoneVerification(verifiedUser, PENDING, "hash", 0, NOW));

        assertEquals(2, repository.deleteExpired(NOW));

        assertTrue(repository.findByUserId(userId).isEmpty());
        assertTrue(repository.findByUserId(verifiedUser).isEmpty());
        assertTrue(repository.findByUserId(otherUser).isPresent());
        assertTrue(phones.findByUserId(verifiedUser).isPresent());
        assertEquals(0, jdbcClient.sql("SELECT count(*) FROM user_phones WHERE user_id = ?").param(userId)
                .query(Integer.class).single());
    }

    /**
     * Builds a verification.
     *
     * @param user      user of the verification.
     * @param expiresAt expiry instant.
     * @return the verification.
     */
    private PhoneVerification verification(final UUID user, final Instant expiresAt) {
        return new PhoneVerification(user, PENDING, "hash", 0, expiresAt);
    }

    /**
     * Inserts a user.
     *
     * @return its identifier.
     */
    private UUID insertUser() {
        final var id = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(id, "user-" + id).update();
        return id;
    }
}
