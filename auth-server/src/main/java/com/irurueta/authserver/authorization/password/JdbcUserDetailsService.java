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

package com.irurueta.authserver.authorization.password;

import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * {@link UserDetailsService} reading users from the {@code users}, {@code user_authorities} and
 * {@code user_passwords} tables.
 */
public class JdbcUserDetailsService implements UserDetailsService {

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

    /**
     * Creates the service.
     *
     * @param template JDBC template of the application datasource.
     */
    public JdbcUserDetailsService(final JdbcTemplate template) {
        this(JdbcClient.create(template));
    }

    /**
     * Creates the service.
     *
     * @param client JDBC client used to run the queries.
     */
    JdbcUserDetailsService(final JdbcClient client) {
        this.jdbcClient = client;
    }

    // tag::password-load-user[]
    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        final var row = jdbcClient.sql(FIND_USER).param(username)
                .query((rs, rowNum) -> new UserRow(rs.getObject("id", UUID.class), rs.getString("username"),
                        rs.getString("encoded_password"), rs.getBoolean("enabled")))
                .optional()
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        final List<String> authorities = jdbcClient.sql(FIND_AUTHORITIES).param(row.id())
                .query(String.class).list();
        return User.withUsername(row.username())
                .password(row.password())
                .disabled(!row.enabled())
                .authorities(AuthorityUtils.createAuthorityList(authorities))
                .build();
    }
    // end::password-load-user[]

    private record UserRow(UUID id, String username, String password, boolean enabled) {
    }
}
