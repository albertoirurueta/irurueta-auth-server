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
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class PasswordConfigurationTest {

    private final PasswordConfiguration configuration = new PasswordConfiguration();

    @Test
    void userDetailsService_returnsJdbcImplementation() {
        assertThat(configuration.userDetailsService(mock(JdbcTemplate.class)))
                .isInstanceOf(JdbcUserDetailsService.class);
    }

    @Test
    void passwordEncoder_encodesAndMatches() {
        final var encoder = configuration.passwordEncoder();

        assertThat(encoder.matches("secret", encoder.encode("secret"))).isTrue();
    }
}
