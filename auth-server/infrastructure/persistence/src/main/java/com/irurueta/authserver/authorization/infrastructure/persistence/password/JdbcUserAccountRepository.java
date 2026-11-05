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

package com.irurueta.authserver.authorization.infrastructure.persistence.password;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link UserAccountRepository} reading user accounts from the {@code users}, {@code user_authorities} and
 * {@code user_passwords} tables.
 */
@Repository
@RequiredArgsConstructor
public class JdbcUserAccountRepository implements UserAccountRepository {

    // tag::password-load-user[]
    /** Columns selected for an account. */
    private static final String SELECT_USER = """
            SELECT u.id, u.username, u.enabled, u.email, u.email_verified, u.tenant, p.encoded_password
            FROM users u JOIN user_passwords p ON p.user_id = u.id
            """;

    /** Query returning the user and its encoded password by username. */
    private static final String FIND_USER = SELECT_USER + "WHERE u.username = ?";
    // end::password-load-user[]

    /** Query returning the user and its encoded password by id. */
    private static final String FIND_USER_BY_ID = SELECT_USER + "WHERE u.id = ?";

    /** Query returning the user and its encoded password by e-mail address, ignoring case. */
    private static final String FIND_USER_BY_EMAIL = SELECT_USER + "WHERE lower(u.email) = lower(?)";

    /** Statement inserting a user, or replacing the columns of the user that has the same id. */
    private static final String UPSERT_USER = """
            INSERT INTO users (id, username, enabled, email, email_verified, tenant)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO UPDATE SET username = EXCLUDED.username, enabled = EXCLUDED.enabled,
                email = EXCLUDED.email, email_verified = EXCLUDED.email_verified, tenant = EXCLUDED.tenant,
                updated_at = CURRENT_TIMESTAMP
            """;

    /** Statement inserting an encoded password, or replacing the stored one. */
    private static final String UPSERT_PASSWORD = """
            INSERT INTO user_passwords (user_id, encoded_password) VALUES (?, ?)
            ON CONFLICT (user_id) DO UPDATE SET encoded_password = EXCLUDED.encoded_password,
                updated_at = CURRENT_TIMESTAMP
            """;

    // tag::password-load-user[]
    /** Query returning the authorities of a user by user id. */
    private static final String FIND_AUTHORITIES = """
            SELECT authority
            FROM user_authorities
            WHERE user_id = ?
            ORDER BY authority
            """;
    // end::password-load-user[]

    // tag::account-verify-once[]
    /**
     * Statement that verifies the e-mail address and enables the account, only while the address is still
     * unverified: a verification link is effective once, so replaying it cannot re-enable an account that was
     * disabled afterwards.
     */
    private static final String MARK_EMAIL_VERIFIED = """
            UPDATE users SET email_verified = TRUE, enabled = TRUE, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND email_verified = FALSE
            """;
    // end::account-verify-once[]

    /** JDBC client used to run the queries. */
    private final JdbcClient jdbcClient;

    /** Maps a user row, without its authorities. */
    private final UserAccountRowMapper userAccountRowMapper;

    // tag::password-load-user[]
    @Override
    public Optional<UserAccount> findByUsername(final String username) {
        return findOne(FIND_USER, username);
    }
    // end::password-load-user[]

    @Override
    public Optional<UserAccount> findById(final UUID id) {
        return findOne(FIND_USER_BY_ID, id);
    }

    @Override
    public Optional<UserAccount> findByEmail(final String email) {
        return findOne(FIND_USER_BY_EMAIL, email);
    }

    @Override
    public boolean existsByUsername(final String username) {
        return jdbcClient.sql("SELECT count(*) FROM users WHERE username = ?").param(username)
                .query(Integer.class).single() > 0;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Several statements: runs in the caller's transaction, which the use case opens (transactions are
     * demarcated by the use cases, never by the adapters).
     */
    @Override
    public void save(final UserAccount account) {
        jdbcClient.sql(UPSERT_USER)
                .params(account.id(), account.username(), account.enabled(), account.email(),
                        account.emailVerified(), account.tenant())
                .update();
        jdbcClient.sql(UPSERT_PASSWORD).params(account.id(), account.encodedPassword()).update();
        jdbcClient.sql("DELETE FROM user_authorities WHERE user_id = ?").param(account.id()).update();
        for (final var authority : account.authorities()) {
            jdbcClient.sql("INSERT INTO user_authorities (user_id, authority) VALUES (?, ?)")
                    .params(account.id(), authority).update();
        }
    }

    @Override
    public void updatePassword(final UUID userId, final String encodedPassword) {
        jdbcClient.sql("UPDATE user_passwords SET encoded_password = ? WHERE user_id = ?")
                .params(encodedPassword, userId).update();
    }

    @Override
    public boolean markEmailVerified(final UUID userId) {
        return jdbcClient.sql(MARK_EMAIL_VERIFIED).param(userId).update() > 0;
    }

    // tag::password-load-user[]
    /**
     * Loads one account, with its authorities.
     *
     * @param sql   query selecting the user row by one parameter.
     * @param value value of the parameter.
     * @return the account, or an empty optional when no row matches.
     */
    private Optional<UserAccount> findOne(final String sql, final Object value) {
        return jdbcClient.sql(sql).param(value)
                .query(userAccountRowMapper)
                .optional()
                .map(row -> row.toUserAccount(
                        jdbcClient.sql(FIND_AUTHORITIES).param(row.id()).query(String.class).list()));
    }
    // end::password-load-user[]
}
