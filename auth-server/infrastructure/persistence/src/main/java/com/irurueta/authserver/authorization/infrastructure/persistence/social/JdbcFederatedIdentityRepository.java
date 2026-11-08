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
package com.irurueta.authserver.authorization.infrastructure.persistence.social;

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.toTimestamp;

import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityRepository;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link FederatedIdentityRepository} over the {@code federated_identities} table. It joins the transaction of its
 * caller, in which {@link #lockSubject} takes a PostgreSQL transaction-level advisory lock on the provider's identity,
 * so two first sign-ins of the same person are serialized and the unique constraint on (provider, subject) is never
 * hit (a violation would abort the caller's transaction).
 */
@Repository
@RequiredArgsConstructor
public class JdbcFederatedIdentityRepository implements FederatedIdentityRepository {

    /** First key of the advisory locks of the identities, which keeps them apart from every other advisory lock. */
    static final int SUBJECT_LOCK_NAMESPACE = 700;

    /** Statement taking the advisory lock of an identity, released when the caller's transaction ends. */
    private static final String LOCK_SUBJECT = "SELECT pg_advisory_xact_lock(?, hashtext(?))";

    /** Columns selected for every query. */
    private static final String COLUMNS = "id, user_id, provider, subject, email, linked_at, last_login_at";

    /** Query returning the link of a provider's subject. */
    private static final String FIND_BY_SUBJECT = "SELECT " + COLUMNS
            + " FROM federated_identities WHERE provider = ? AND subject = ?";

    /** Query returning the links of an account, oldest first. */
    private static final String FIND_BY_USER = "SELECT " + COLUMNS
            + " FROM federated_identities WHERE user_id = ? ORDER BY linked_at, id";

    /** Query returning one link of an account. */
    private static final String FIND_BY_ID_AND_USER = "SELECT " + COLUMNS
            + " FROM federated_identities WHERE id = ? AND user_id = ?";

    /** Statement inserting a link, or updating the e-mail address and last sign-in of the one with the same id. */
    private static final String UPSERT = """
            INSERT INTO federated_identities (id, user_id, provider, subject, email, linked_at, last_login_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, last_login_at = EXCLUDED.last_login_at
            """;

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Maps a row to an identity. */
    private final FederatedIdentityRowMapper federatedIdentityRowMapper;

    // tag::social-lock-subject[]
    @Override
    public void lockSubject(final IdentityProvider provider, final String subject) {
        jdbcClient.sql(LOCK_SUBJECT).params(SUBJECT_LOCK_NAMESPACE, provider.id() + ":" + subject)
                .query((rs, rowNum) -> Boolean.TRUE).list();
    }
    // end::social-lock-subject[]

    @Override
    public Optional<FederatedIdentity> findByProviderAndSubject(final IdentityProvider provider,
                                                                final String subject) {
        return jdbcClient.sql(FIND_BY_SUBJECT).params(provider.id(), subject).query(federatedIdentityRowMapper)
                .optional();
    }

    @Override
    public List<FederatedIdentity> findByUser(final UUID userId) {
        return jdbcClient.sql(FIND_BY_USER).param(userId).query(federatedIdentityRowMapper).list();
    }

    @Override
    public Optional<FederatedIdentity> findByIdAndUser(final UUID id, final UUID userId) {
        return jdbcClient.sql(FIND_BY_ID_AND_USER).params(id, userId).query(federatedIdentityRowMapper).optional();
    }

    @Override
    public FederatedIdentity save(final FederatedIdentity identity) {
        jdbcClient.sql(UPSERT)
                .params(identity.id(), identity.userId(), identity.provider().id(), identity.subject(),
                        identity.email(), toTimestamp(identity.linkedAt()), toTimestamp(identity.lastLoginAt()))
                .update();
        return identity;
    }

    @Override
    public boolean delete(final UUID id, final UUID userId) {
        return jdbcClient.sql("DELETE FROM federated_identities WHERE id = ? AND user_id = ?").params(id, userId)
                .update() > 0;
    }

    @Override
    public long countByUser(final UUID userId) {
        return jdbcClient.sql("SELECT count(*) FROM federated_identities WHERE user_id = ?").param(userId)
                .query(Long.class).single();
    }
}
