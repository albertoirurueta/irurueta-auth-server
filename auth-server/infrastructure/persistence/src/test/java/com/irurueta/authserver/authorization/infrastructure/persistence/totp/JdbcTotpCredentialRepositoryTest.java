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

package com.irurueta.authserver.authorization.infrastructure.persistence.totp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Unit tests of {@link JdbcTotpCredentialRepository}, with the JDBC client mocked. The statements themselves run
 * against PostgreSQL in {@link JdbcTotpCredentialRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcTotpCredentialRepositoryTest {

    /** Step used by the tests. */
    private static final long STEP = 42L;

    /** Instant the credential was created. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Identifier of the user. */
    private final UUID userId = UUID.randomUUID();

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Maps a row to a credential; mocked so the tests control the mapped credentials. */
    @Mock
    private TotpCredentialRowMapper totpCredentialRowMapper;

    /** Repository under test. */
    @InjectMocks
    private JdbcTotpCredentialRepository repository;

    /**
     * Verifies that the credential the query returns is passed through.
     */
    @Test
    void findByUser_whenRowMatches_returnsMappedCredential() {
        final var credential = new TotpCredential(userId, new byte[] {1}, true, STEP, CREATED_AT);
        when(client.sql(any(String.class)).param(userId).query(totpCredentialRowMapper).optional())
                .thenReturn(Optional.of(credential));

        assertSame(credential, repository.findByUser(userId).orElseThrow());
    }

    /**
     * Verifies that an empty result is returned when the user has no credential.
     */
    @Test
    void findByUser_whenNoRowMatches_returnsEmpty() {
        when(client.sql(any(String.class)).param(userId).query(totpCredentialRowMapper).optional())
                .thenReturn(Optional.empty());

        assertTrue(repository.findByUser(userId).isEmpty());
    }

    /**
     * Verifies that a credential is upserted with its instant converted to UTC.
     */
    @Test
    void save_whenCredentialIsGiven_upsertsTheRow() {
        final var secret = new byte[] {1, 2};
        final var credential = new TotpCredential(userId, secret, false, TotpCredential.NEVER_USED, CREATED_AT);

        repository.save(credential);

        verify(client.sql(any(String.class)).params(userId, secret, false, TotpCredential.NEVER_USED,
                CREATED_AT.atOffset(ZoneOffset.UTC))).update();
    }

    /**
     * Verifies that the credential of the user is confirmed.
     */
    @Test
    void confirm_whenUserIsGiven_updatesTheRow() {
        repository.confirm(userId);

        verify(client.sql(any(String.class)).param(userId)).update();
    }

    /**
     * Verifies that {@code true} is returned when the conditional update changed a row.
     */
    @Test
    void advanceLastUsedStep_whenStepIsNewer_returnsTrue() {
        when(client.sql(any(String.class)).params(STEP, userId, STEP).update()).thenReturn(1);

        assertTrue(repository.advanceLastUsedStep(userId, STEP));
    }

    /**
     * Verifies that {@code false} is returned when the conditional update changed no row.
     */
    @Test
    void advanceLastUsedStep_whenStepIsNotNewer_returnsFalse() {
        when(client.sql(any(String.class)).params(STEP, userId, STEP).update()).thenReturn(0);

        assertFalse(repository.advanceLastUsedStep(userId, STEP));
    }

    /**
     * Verifies that the credential of the user is deleted.
     */
    @Test
    void deleteByUser_whenUserIsGiven_deletesTheRow() {
        repository.deleteByUser(userId);

        verify(client.sql(any(String.class)).param(userId)).update();
    }
}
