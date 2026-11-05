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

    /** Query returning the user and its encoded password by username. */
    private static final String FIND_USER = """
            SELECT u.id, u.username, u.enabled, p.encoded_password
            FROM users u JOIN user_passwords p ON p.user_id = u.id
            WHERE u.username = ?
            """;

    /** Query returning the authorities of a user by user id. */
    private static final String FIND_AUTHORITIES = """
            SELECT authority
            FROM user_authorities
            WHERE user_id = ?
            ORDER BY authority
            """;

    /** JDBC client used to run the queries. */
    private final JdbcClient jdbcClient;

    // tag::password-load-user[]
    @Override
    public Optional<UserAccount> findByUsername(final String username) {
        return jdbcClient.sql(FIND_USER).param(username)
                .query((rs, rowNum) -> new UserRow(rs.getObject("id", UUID.class), rs.getString("username"),
                        rs.getString("encoded_password"), rs.getBoolean("enabled")))
                .optional()
                .map(row -> new UserAccount(row.id(), row.username(), row.password(), row.enabled(),
                        jdbcClient.sql(FIND_AUTHORITIES).param(row.id()).query(String.class).list()));
    }
    // end::password-load-user[]

    /**
     * Columns of the user row, before its authorities are loaded.
     *
     * @param id       identifier of the user.
     * @param username name the user signs in with.
     * @param password encoded password.
     * @param enabled  whether the account is enabled.
     */
    private record UserRow(UUID id, String username, String password, boolean enabled) {
    }
}
