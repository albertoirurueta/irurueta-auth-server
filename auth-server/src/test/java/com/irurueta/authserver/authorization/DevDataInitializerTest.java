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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

class DevDataInitializerTest {

    private final JdbcClient jdbcClient = mock(JdbcClient.class, RETURNS_DEEP_STUBS);

    private final InMemoryRegisteredClientRepository clients = new InMemoryRegisteredClientRepository(
            RegisteredClient.withId("other").clientId("other")
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build());

    @SuppressWarnings("deprecation")
    private final DevDataInitializer initializer = new DevDataInitializer(jdbcClient,
            NoOpPasswordEncoder.getInstance(), clients);

    private void userCount(final int count) {
        when(jdbcClient.sql(anyString()).param(DevDataInitializer.DEMO_USERNAME).query(Integer.class).single())
                .thenReturn(count);
    }

    @Test
    void run_whenEmpty_createsUserAndClient() {
        userCount(0);

        initializer.run(new DefaultApplicationArguments());

        verify(jdbcClient, org.mockito.Mockito.atLeast(4)).sql(anyString());
        final var client = clients.findByClientId(DevDataInitializer.BFF_CLIENT_ID);
        assertThat(client).isNotNull();
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getRedirectUris()).containsExactly(DevDataInitializer.BFF_REDIRECT_URI);
        assertThat(client.getScopes()).containsExactlyInAnyOrder("openid", "profile");
        assertThat(client.getAuthorizationGrantTypes()).containsExactlyInAnyOrder(
                AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN);
        assertThat(client.getClientSecret()).isNotBlank();
    }

    @Test
    void run_whenDataExists_doesNotCreateAnything() {
        userCount(1);
        initializer.run(new DefaultApplicationArguments());
        final var first = clients.findByClientId(DevDataInitializer.BFF_CLIENT_ID);

        initializer.run(new DefaultApplicationArguments());

        assertThat(clients.findByClientId(DevDataInitializer.BFF_CLIENT_ID)).isSameAs(first);
        verify(jdbcClient, never()).sql("INSERT INTO users (id, username) VALUES (?, ?)");
    }
}
