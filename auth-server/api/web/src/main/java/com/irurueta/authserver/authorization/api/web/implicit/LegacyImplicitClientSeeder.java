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
package com.irurueta.authserver.authorization.api.web.implicit;

import com.irurueta.authserver.authorization.application.clients.SeedRegisteredClientsUseCase;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;

/**
 * Registers the one client of the legacy implicit flow at start-up, when it does not exist yet: public, grant
 * {@code implicit} only (no refresh token, no consent), one redirect URI, a restricted scope and audience and the
 * lifetime of the flow.
 */
@Slf4j
@RequiredArgsConstructor
public class LegacyImplicitClientSeeder implements ApplicationRunner {

    /** Seeds the clients. */
    private final SeedRegisteredClientsUseCase seedRegisteredClientsUseCase;

    /** Settings of the flow. */
    private final LegacyImplicitProperties properties;

    /**
     * Seeds the client.
     *
     * @param args the application arguments.
     */
    @Override
    public void run(final ApplicationArguments args) {
        final var result = seedRegisteredClientsUseCase.execute(List.of(definition()), Map.of());
        log.warn("The legacy implicit flow is enabled for client {} (demo only, never enable it in production); "
                + "created: {}", properties.clientId(), result.created());
    }

    /**
     * Defines the client.
     *
     * @return the client.
     */
    ClientRegistration definition() {
        return new ClientRegistration(properties.clientId(), "Legacy implicit demo", false, List.of("none"),
                List.of(ClientRegistration.GRANT_IMPLICIT), List.of(properties.redirectUri()), properties.scopes(),
                false, List.of(properties.audience()), properties.accessTokenTtl(), properties.accessTokenTtl(),
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false, null, null, null, null,
                false);
    }
}
