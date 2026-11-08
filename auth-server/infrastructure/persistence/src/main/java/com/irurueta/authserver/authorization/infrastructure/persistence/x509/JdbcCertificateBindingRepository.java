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

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.toTimestamp;

import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link CertificateBindingRepository} over the {@code x509_certificates} table. It joins the transaction of its
 * caller.
 */
@Repository
@RequiredArgsConstructor
public class JdbcCertificateBindingRepository implements CertificateBindingRepository {

    /** Columns selected for every query. */
    private static final String COLUMNS = "id, user_id, fingerprint_sha256, subject_dn, created_at";

    /** Query returning the binding of a certificate. */
    private static final String FIND_BY_FINGERPRINT = "SELECT " + COLUMNS
            + " FROM x509_certificates WHERE fingerprint_sha256 = ?";

    /** Query returning the bindings of an account, oldest first. */
    private static final String FIND_BY_USER = "SELECT " + COLUMNS
            + " FROM x509_certificates WHERE user_id = ? ORDER BY created_at, id";

    /** Statement storing a binding. */
    private static final String INSERT = """
            INSERT INTO x509_certificates (id, user_id, fingerprint_sha256, subject_dn, created_at)
            VALUES (?, ?, ?, ?, ?)
            """;

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Maps a row to a binding. */
    private final CertificateBindingRowMapper certificateBindingRowMapper;

    @Override
    public Optional<CertificateBinding> findByFingerprintSha256(final String fingerprintSha256) {
        return jdbcClient.sql(FIND_BY_FINGERPRINT).param(fingerprintSha256).query(certificateBindingRowMapper)
                .optional();
    }

    @Override
    public List<CertificateBinding> findByUser(final UUID userId) {
        return jdbcClient.sql(FIND_BY_USER).param(userId).query(certificateBindingRowMapper).list();
    }

    @Override
    public CertificateBinding save(final CertificateBinding binding) {
        jdbcClient.sql(INSERT)
                .params(binding.id(), binding.userId(), binding.fingerprintSha256(), binding.subjectDn(),
                        toTimestamp(binding.createdAt()))
                .update();
        return binding;
    }

    @Override
    public boolean delete(final UUID id, final UUID userId) {
        return jdbcClient.sql("DELETE FROM x509_certificates WHERE id = ? AND user_id = ?").params(id, userId)
                .update() > 0;
    }
}
