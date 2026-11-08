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
package com.irurueta.authserver.authorization.infrastructure.persistence.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
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
 * Unit tests of {@link JdbcCertificateBindingRepository}, with the JDBC client mocked. The statements themselves run
 * against PostgreSQL in {@link JdbcCertificateBindingRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcCertificateBindingRepositoryTest {

    /** Fingerprint used by the tests. */
    private static final String FINGERPRINT = "e".repeat(CertificateBinding.FINGERPRINT_LENGTH);

    /** Subject used by the tests. */
    private static final String SUBJECT = "CN=alice";

    /** Instant the certificate was bound. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Identifier of the binding. */
    private final UUID id = UUID.randomUUID();

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Maps a row to a binding; mocked so the tests control the mapped bindings. */
    @Mock
    private CertificateBindingRowMapper certificateBindingRowMapper;

    /** Repository under test. */
    @InjectMocks
    private JdbcCertificateBindingRepository repository;

    /**
     * Verifies that the binding the query returns is mapped with the row mapper.
     */
    @Test
    void findByFingerprintSha256_whenRowMatches_returnsMappedBinding() {
        final var binding = binding();
        when(client.sql(any(String.class)).param(FINGERPRINT).query(certificateBindingRowMapper).optional())
                .thenReturn(Optional.of(binding));

        assertSame(binding, repository.findByFingerprintSha256(FINGERPRINT).orElseThrow());
    }

    /**
     * Verifies that the bindings of the account are listed through the row mapper.
     */
    @Test
    void findByUser_whenAccountHasBindings_returnsMappedBindings() {
        final var bindings = List.of(binding());
        when(client.sql(any(String.class)).param(userId).query(certificateBindingRowMapper).list())
                .thenReturn(bindings);

        assertEquals(bindings, repository.findByUser(userId));
    }

    /**
     * Verifies that a binding is stored with its timestamp converted to UTC and returned unchanged.
     */
    @Test
    void save_whenBindingIsValid_insertsTheRowAndReturnsIt() {
        final var binding = binding();

        assertSame(binding, repository.save(binding));

        verify(client.sql(any(String.class)).params(id, userId, FINGERPRINT, SUBJECT,
                CREATED_AT.atOffset(ZoneOffset.UTC))).update();
    }

    /**
     * Verifies that deleting reports {@code true} when a row was deleted and {@code false} otherwise.
     */
    @Test
    void delete_whenRowDeletedOrNot_reportsIt() {
        when(client.sql(any(String.class)).params(id, userId).update()).thenReturn(1, 0);

        assertTrue(repository.delete(id, userId));
        assertFalse(repository.delete(id, userId));
    }

    /**
     * Builds the binding used by the tests.
     *
     * @return the binding.
     */
    private CertificateBinding binding() {
        return new CertificateBinding(id, userId, FINGERPRINT, SUBJECT, CREATED_AT);
    }
}
