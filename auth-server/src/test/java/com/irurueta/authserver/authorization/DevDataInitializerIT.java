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

package com.irurueta.authserver.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import com.irurueta.authserver.testsupport.PostgresIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;

@PostgresIT
@ActiveProfiles("dev")
class DevDataInitializerIT {

    @Autowired
    private DevDataInitializer initializer;

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private RegisteredClientRepository clients;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void run_createsDataOnceAndIsIdempotent() {
        // the runner already executed once at context start; running it again must not duplicate anything
        initializer.run(new DefaultApplicationArguments());
        initializer.run(new DefaultApplicationArguments());

        assertThat(jdbcClient.sql("SELECT count(*) FROM users WHERE username = 'demo'")
                .query(Integer.class).single()).isEqualTo(1);
        assertThat(jdbcClient.sql("SELECT count(*) FROM oauth2_registered_client WHERE client_id = 'bff'")
                .query(Integer.class).single()).isEqualTo(1);

        final var user = userDetailsService.loadUserByUsername("demo");
        assertThat(user.getAuthorities()).extracting("authority").containsExactly("ROLE_USER");
        assertThat(user.getPassword()).startsWith("{bcrypt}");

        final var client = clients.findByClientId("bff");
        assertThat(client).isNotNull();
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(passwordEncoder.upgradeEncoding(client.getClientSecret())).isFalse();
    }
}
