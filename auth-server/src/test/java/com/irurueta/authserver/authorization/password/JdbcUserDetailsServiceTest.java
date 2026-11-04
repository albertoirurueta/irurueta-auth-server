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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.sql.ResultSet;
import java.util.List;
import java.util.Optional;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

class JdbcUserDetailsServiceTest {

    private final JdbcClient client = mock(JdbcClient.class, RETURNS_DEEP_STUBS);

    private final JdbcUserDetailsService service = new JdbcUserDetailsService(client);

    @Test
    @SuppressWarnings("unchecked")
    void loadUserByUsername_whenMissing_throws() {
        when(client.sql(any(String.class)).param(any()).query(any(RowMapper.class)).optional())
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.loadUserByUsername("x")).isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void loadUserByUsername_whenFound_buildsUser() throws Exception {
        final var rs = mock(ResultSet.class);
        when(rs.getString("username")).thenReturn("a");
        when(rs.getString("encoded_password")).thenReturn("pwd");
        when(rs.getBoolean("enabled")).thenReturn(false);
        final var captor = ArgumentCaptor.forClass(RowMapper.class);
        final var spec = client.sql(any(String.class)).param(any());
        when(spec.query(captor.capture()).optional()).thenAnswer(
                invocation -> Optional.of(captor.getValue().mapRow(rs, 0)));
        when(spec.query(String.class).list()).thenReturn(List.of("ROLE_USER"));

        final var user = service.loadUserByUsername("a");

        assertThat(user.getUsername()).isEqualTo("a");
        assertThat(user.getPassword()).isEqualTo("pwd");
        assertThat(user.isEnabled()).isFalse();
        assertThat(user.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsExactly("ROLE_USER");
    }
}
