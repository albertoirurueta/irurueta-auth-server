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

package com.irurueta.authserver.authorization.api.web.clients;

import com.irurueta.authserver.authorization.api.web.ApiSecurityConfig;
import com.irurueta.authserver.authorization.application.clients.DefaultClientDefinitions;
import com.irurueta.authserver.authorization.application.clients.SeedRegisteredClientsUseCase;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import java.util.ArrayList;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

// tag::clients-seeding[]
/**
 * Seeds the configured default clients at startup. The run is idempotent: clients that already exist are left
 * alone. Only the clients whose redirect URIs are configured in {@link ClientSeedProperties} are seeded, so a
 * deployment never gets a client (or a {@code localhost} redirect URI) it did not ask for. The secret of the
 * confidential {@code bff} client comes from the environment; when it is not configured, the confidential client is
 * skipped with a warning instead of being created with a weak secret.
 */
@Slf4j
@Component
@EnableConfigurationProperties(ClientSeedProperties.class)
@RequiredArgsConstructor
public class ClientSeeder implements ApplicationRunner {

    /** Seeds the clients. */
    private final SeedRegisteredClientsUseCase seedRegisteredClientsUseCase;

    /** Seed configuration. */
    private final ClientSeedProperties properties;

    /** Audience of the authorization server's own API, given to the seeded clients. */
    @Value("${" + ApiSecurityConfig.API_AUDIENCE_PROPERTY + ":" + DefaultClientDefinitions.DEFAULT_API_AUDIENCE + "}")
    private final String apiAudience;

    /**
     * Seeds the configured default clients that do not exist yet.
     *
     * @param args the application arguments.
     */
    @Override
    public void run(final ApplicationArguments args) {
        final var definitions = new ArrayList<ClientRegistration>();
        if (properties.bff().isConfigured()) {
            definitions.add(DefaultClientDefinitions.bff(properties.bff().redirectUris(), apiAudience,
                    properties.bff().postLogoutRedirectUris()));
        }
        if (properties.spaPublic().isConfigured()) {
            definitions.add(DefaultClientDefinitions.spaPublic(properties.spaPublic().redirectUris(), apiAudience,
                    properties.spaPublic().postLogoutRedirectUris()));
        }
        final var secrets = StringUtils.hasText(properties.bffSecret())
                ? Map.of(DefaultClientDefinitions.BFF_CLIENT_ID, properties.bffSecret())
                : Map.<String, String>of();
        final var result = seedRegisteredClientsUseCase.execute(definitions, secrets);
        log.info("Seeded {} default client(s): {}", result.created().size(), result.created());
        if (!result.skipped().isEmpty()) {
            log.warn("Skipped the confidential client(s) {}: no secret is configured "
                    + "(set AUTHSERVER_BFF_CLIENT_SECRET)", result.skipped());
        }
    }
}
// end::clients-seeding[]
