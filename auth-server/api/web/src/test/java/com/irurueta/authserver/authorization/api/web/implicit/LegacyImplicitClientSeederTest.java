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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.clients.SeedRegisteredClientsUseCase;
import com.irurueta.authserver.authorization.application.clients.SeedResult;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;

/**
 * Unit tests of {@link LegacyImplicitClientSeeder}.
 */
@ExtendWith(MockitoExtension.class)
class LegacyImplicitClientSeederTest {

    /** Lifetime of the tokens. */
    private static final Duration TTL = Duration.ofMinutes(5);

    /** Redirect URI. */
    private static final String REDIRECT_URI = "http://localhost:9000/legacy-implicit/";

    /** Seeds the clients. */
    @Mock
    private SeedRegisteredClientsUseCase seedRegisteredClientsUseCase;

    /** Settings of the flow. */
    private final LegacyImplicitProperties properties = new LegacyImplicitProperties("legacy-implicit-spa",
            REDIRECT_URI, List.of("documents.read"), "resource-server", TTL);

    /** Seeder under test. */
    private LegacyImplicitClientSeeder seeder;

    /**
     * Creates the seeder.
     */
    @BeforeEach
    void setUp() {
        seeder = new LegacyImplicitClientSeeder(seedRegisteredClientsUseCase, properties);
    }

    /**
     * Verifies that the client is public, implicit only, without consent and with the configured limits.
     */
    @Test
    void definition_whenCalled_describesARestrictedPublicImplicitClient() {
        final var definition = seeder.definition();

        assertEquals("legacy-implicit-spa", definition.clientId());
        assertFalse(definition.confidential());
        assertEquals(List.of("none"), definition.authMethods());
        assertEquals(List.of("implicit"), definition.grantTypes());
        assertEquals(List.of(REDIRECT_URI), definition.redirectUris());
        assertEquals(List.of("documents.read"), definition.scopes());
        assertEquals(List.of("resource-server"), definition.audiences());
        assertEquals(TTL, definition.accessTokenTtl());
        assertFalse(definition.requireConsent());
        assertFalse(definition.mfaRequired());
        assertTrue(definition.grantTypes().stream().noneMatch(ClientRegistration.GRANT_REFRESH_TOKEN::equals));
    }

    /**
     * Verifies that the run seeds the client without a secret.
     */
    @Test
    void run_whenCalled_seedsTheClient() {
        when(seedRegisteredClientsUseCase.execute(anyList(),
                anyMap()))
                .thenReturn(new SeedResult(List.of("legacy-implicit-spa"), List.of()));

        seeder.run(new DefaultApplicationArguments());

        final var captor = ArgumentCaptor.<List<ClientRegistration>>captor();
        verify(seedRegisteredClientsUseCase).execute(captor.capture(), eq(Map.of()));
        assertEquals("legacy-implicit-spa", captor.getValue().getFirst().clientId());
    }
}
