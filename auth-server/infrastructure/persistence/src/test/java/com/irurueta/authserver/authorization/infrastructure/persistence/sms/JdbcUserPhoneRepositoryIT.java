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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerification;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcUserPhoneRepository} against PostgreSQL with the real migrations.
 */
class JdbcUserPhoneRepositoryIT {

    /** First phone number. */
    private static final PhoneNumber PHONE_A = new PhoneNumber("+34600000011");

    /** Second phone number. */
    private static final PhoneNumber PHONE_B = new PhoneNumber("+34600000012");

    /** Instant used by the tests, truncated to what the database stores. */
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.MILLIS);

    /** Number of failed attempts of the pending verification. */
    private static final int ATTEMPTS = 2;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcUserPhoneRepository repository;

    /** Repository of the pending verifications, to prove the columns are independent. */
    private static JdbcPhoneVerificationRepository verifications;

    /** First user. */
    private UUID userA;

    /** Second user. */
    private UUID userB;

    /**
     * Connects to the migrated database and builds the repositories.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcUserPhoneRepository(jdbcClient, new UserPhoneRowMapper());
        verifications = new JdbcPhoneVerificationRepository(jdbcClient, new PhoneVerificationRowMapper());
    }

    /**
     * Removes the data of the previous test and inserts two users.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
        userA = insertUser();
        userB = insertUser();
    }

    /**
     * Verifies that a saved phone is found by user and by number.
     */
    @Test
    void save_whenPhoneIsFree_storesItAndReturnsTrue() {
        final var phone = new UserPhone(userA, PHONE_A, NOW);

        assertTrue(repository.save(phone));

        assertEquals(phone, repository.findByUserId(userA).orElseThrow());
        assertEquals(phone, repository.findByPhone(PHONE_A).orElseThrow());
        assertTrue(repository.findByUserId(userB).isEmpty());
        assertTrue(repository.findByPhone(PHONE_B).isEmpty());
    }

    /**
     * Verifies that saving again replaces the number of the same user.
     */
    @Test
    void save_whenUserAlreadyHasPhone_replacesIt() {
        repository.save(new UserPhone(userA, PHONE_A, NOW));
        final var replacement = new UserPhone(userA, PHONE_B, NOW.plusSeconds(1));

        assertTrue(repository.save(replacement));

        assertEquals(replacement, repository.findByUserId(userA).orElseThrow());
        assertTrue(repository.findByPhone(PHONE_A).isEmpty());
    }

    /**
     * Verifies that a number of another user is refused and nothing changes.
     */
    @Test
    void save_whenPhoneBelongsToAnotherUser_returnsFalse() {
        final var owner = new UserPhone(userA, PHONE_A, NOW);
        repository.save(owner);

        assertFalse(repository.save(new UserPhone(userB, PHONE_A, NOW)));

        assertEquals(owner, repository.findByPhone(PHONE_A).orElseThrow());
        assertTrue(repository.findByUserId(userB).isEmpty());
    }

    /**
     * Verifies that a user who holds a number can save it again.
     */
    @Test
    void save_whenSamePhoneOfSameUser_returnsTrue() {
        repository.save(new UserPhone(userA, PHONE_A, NOW));

        assertTrue(repository.save(new UserPhone(userA, PHONE_A, NOW.plusSeconds(1))));
    }

    /**
     * Verifies that saving the verified phone leaves the pending verification untouched.
     */
    @Test
    void save_whenVerificationIsPending_keepsPendingColumns() {
        final var pending = new PhoneVerification(userA, PHONE_B, "hash", ATTEMPTS, NOW.plusSeconds(60));
        verifications.save(pending);

        repository.save(new UserPhone(userA, PHONE_A, NOW));

        assertEquals(pending, verifications.findByUserId(userA).orElseThrow());
    }

    /**
     * Verifies that deleting clears the verified phone and the row when nothing else remains.
     */
    @Test
    void deleteByUserId_whenOnlyVerifiedPhone_removesRow() {
        repository.save(new UserPhone(userA, PHONE_A, NOW));

        repository.deleteByUserId(userA);

        assertTrue(repository.findByUserId(userA).isEmpty());
        assertEquals(0, jdbcClient.sql("SELECT count(*) FROM user_phones WHERE user_id = ?").param(userA)
                .query(Integer.class).single());
        assertTrue(repository.save(new UserPhone(userB, PHONE_A, NOW)));
    }

    /**
     * Verifies that deleting keeps the pending verification.
     */
    @Test
    void deleteByUserId_whenVerificationIsPending_keepsPendingVerification() {
        final var pending = new PhoneVerification(userA, PHONE_B, "hash", ATTEMPTS, NOW.plusSeconds(60));
        repository.save(new UserPhone(userA, PHONE_A, NOW));
        verifications.save(pending);

        repository.deleteByUserId(userA);

        assertTrue(repository.findByUserId(userA).isEmpty());
        assertEquals(pending, verifications.findByUserId(userA).orElseThrow());
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
