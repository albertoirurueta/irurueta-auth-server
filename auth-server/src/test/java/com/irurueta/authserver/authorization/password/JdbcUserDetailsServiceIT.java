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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@PostgresIT
class JdbcUserDetailsServiceIT {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanUp() {
        jdbcTemplate.update("DELETE FROM users");
    }

    private void insertUser(final String username, final boolean enabled, final String... authorities) {
        final var id = UUID.randomUUID();
        jdbcTemplate.update("INSERT INTO users (id, username, enabled) VALUES (?, ?, ?)", id, username, enabled);
        jdbcTemplate.update("INSERT INTO user_passwords (user_id, encoded_password) VALUES (?, ?)", id, "{noop}secret");
        for (final var authority : authorities) {
            jdbcTemplate.update("INSERT INTO user_authorities (user_id, authority) VALUES (?, ?)", id, authority);
        }
    }

    @Test
    void loadUserByUsername_whenUserExists_returnsUser() {
        insertUser("alice", true, "ROLE_USER");

        final var user = userDetailsService.loadUserByUsername("alice");

        assertThat(user.getUsername()).isEqualTo("alice");
        assertThat(user.getPassword()).isEqualTo("{noop}secret");
        assertThat(user.isEnabled()).isTrue();
    }

    @Test
    void loadUserByUsername_whenUserIsDisabled_returnsDisabledUser() {
        insertUser("bob", false, "ROLE_USER");

        assertThat(userDetailsService.loadUserByUsername("bob").isEnabled()).isFalse();
    }

    @Test
    void loadUserByUsername_whenUserMissing_throwsUsernameNotFoundException() {
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("nobody"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void loadUserByUsername_whenUserHasAuthorities_loadsThem() {
        insertUser("carol", true, "ROLE_USER", "ROLE_ADMIN");

        final var user = userDetailsService.loadUserByUsername("carol");

        assertThat(user.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void loadUserByUsername_whenUserHasNoAuthorities_returnsEmptyAuthorities() {
        insertUser("dave", true);

        assertThat(userDetailsService.loadUserByUsername("dave").getAuthorities()).isEmpty();
    }
}
