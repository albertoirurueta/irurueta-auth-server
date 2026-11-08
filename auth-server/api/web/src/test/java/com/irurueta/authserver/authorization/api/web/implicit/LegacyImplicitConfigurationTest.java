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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.application.clients.SeedRegisteredClientsUseCase;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;

/**
 * Unit tests of {@link LegacyImplicitConfiguration}.
 */
class LegacyImplicitConfigurationTest {

    /** Minutes of the lifetime. */
    private static final int MINUTES = 5;

    /** Expected order of the customizer. */
    private static final int EXPECTED_ORDER = 4;

    /** Lifetime of the tokens. */
    private static final Duration TTL = Duration.ofMinutes(MINUTES);

    /** Settings of the flow. */
    private static final LegacyImplicitProperties PROPERTIES = new LegacyImplicitProperties("legacy-implicit-spa",
            "http://localhost:9000/legacy-implicit/", List.of("documents.read"), "resource-server",
            TTL);

    /** Configuration under test. */
    private final LegacyImplicitConfiguration configuration = new LegacyImplicitConfiguration();

    /**
     * Verifies that the configuration only exists under the legacy profile.
     */
    @Test
    void profile_whenInspected_isTheLegacyImplicitProfile() {
        final var profile = LegacyImplicitConfiguration.class.getAnnotation(Profile.class);

        assertEquals(List.of("legacy-implicit"), List.of(profile.value()));
    }

    /**
     * Verifies that the factory and the customizer are built with the order that follows the client authentication.
     */
    @Test
    @SuppressWarnings("unchecked")
    void legacyImplicitProtocolChainCustomizer_whenCalled_buildsTheCustomizer() {
        final var factory = configuration.legacyImplicitTokenGeneratorFactory(mock(JwtEncoder.class),
                mock(ObjectProvider.class), mock(ObjectProvider.class));
        final var serverSettings = AuthorizationServerSettings.builder().build();

        final var customizer = configuration.legacyImplicitProtocolChainCustomizer(
                mock(RegisteredClientRepository.class), mock(OAuth2AuthorizationService.class), factory,
                serverSettings, mock(MfaAuthorizationManager.class), PROPERTIES);

        assertNotNull(customizer);
        assertEquals(EXPECTED_ORDER, LegacyImplicitProtocolChainCustomizer.ORDER);
    }

    /**
     * Verifies that the seeder is created.
     */
    @Test
    void legacyImplicitClientSeeder_whenCalled_createsTheSeeder() {
        assertNotNull(configuration.legacyImplicitClientSeeder(mock(SeedRegisteredClientsUseCase.class), PROPERTIES));
    }

    /**
     * Verifies that the login customizer permits the demo directory.
     */
    @Test
    @SuppressWarnings("unchecked")
    void legacyImplicitLoginChainCustomizer_whenApplied_authorizesTheRequests() {
        final var http = mock(HttpSecurity.class);
        when(http.authorizeHttpRequests(any())).thenReturn(http);

        configuration.legacyImplicitLoginChainCustomizer().customize(http);

        verify(http).authorizeHttpRequests(any());
    }

    /**
     * Verifies that the demo page is served from the classpath folder.
     */
    @Test
    void addResourceHandlers_whenCalled_servesTheDemoFolder() {
        final var registry = mock(ResourceHandlerRegistry.class, RETURNS_DEEP_STUBS);

        configuration.addResourceHandlers(registry);

        verify(registry).addResourceHandler("/legacy-implicit/**");
    }

    /**
     * Verifies that the demo directory shows the index page.
     */
    @Test
    void addViewControllers_whenCalled_forwardsTheDirectoryToTheIndex() {
        final var registry = mock(ViewControllerRegistry.class, RETURNS_DEEP_STUBS);

        configuration.addViewControllers(registry);

        verify(registry).addViewController("/legacy-implicit/");
        assertTrue(LegacyImplicitConfiguration.DEMO_PATH.endsWith("/"));
    }
}
