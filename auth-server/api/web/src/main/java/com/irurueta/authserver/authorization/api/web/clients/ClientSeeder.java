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

import com.irurueta.authserver.authorization.application.clients.DefaultClientDefinitions;
import com.irurueta.authserver.authorization.application.clients.SeedRegisteredClientsUseCase;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Seeds the default clients at startup. The run is idempotent: clients that already exist are left alone. The
 * secret of the confidential {@code bff} client comes from {@link ClientSeedProperties} (environment); when it is
 * not configured, the confidential client is skipped with a warning instead of being created with a weak secret.
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

    /**
     * Seeds the default clients that do not exist yet.
     *
     * @param args the application arguments.
     */
    @Override
    public void run(final ApplicationArguments args) {
        final var secrets = StringUtils.hasText(properties.bffSecret())
                ? Map.of(DefaultClientDefinitions.BFF_CLIENT_ID, properties.bffSecret())
                : Map.<String, String>of();
        final var result = seedRegisteredClientsUseCase.execute(secrets);
        log.info("Seeded {} default client(s): {}", result.created().size(), result.created());
        if (!result.skipped().isEmpty()) {
            log.warn("Skipped the confidential client(s) {}: no secret is configured "
                    + "(set AUTHSERVER_BFF_CLIENT_SECRET)", result.skipped());
        }
    }
}
