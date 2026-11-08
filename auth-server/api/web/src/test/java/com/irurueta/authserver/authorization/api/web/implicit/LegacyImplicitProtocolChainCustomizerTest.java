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
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationEndpointConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Unit tests of {@link LegacyImplicitProtocolChainCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class LegacyImplicitProtocolChainCustomizerTest {

    /** Expected order of the customizer. */
    private static final int EXPECTED_ORDER = 4;

    /** The converter to install. */
    @Mock
    private AuthenticationConverter converter;

    /** The provider to install. */
    @Mock
    private AuthenticationProvider provider;

    /** The response handler to install. */
    @Mock
    private AuthenticationSuccessHandler responseHandler;

    /** Customizer under test. */
    @InjectMocks
    private LegacyImplicitProtocolChainCustomizer customizer;

    /**
     * Verifies that the order is after the client authentication customizer.
     */
    @Test
    void order_isAfterTheClientAuthenticationCustomizer() {
        assertEquals(EXPECTED_ORDER, LegacyImplicitProtocolChainCustomizer.ORDER);
    }

    /**
     * Verifies that the converter and the provider go first and the response handler is installed.
     */
    @Test
    @SuppressWarnings("unchecked")
    void customize_whenApplied_installsConverterProviderAndHandlerFirst() {
        final var server = mock(OAuth2AuthorizationServerConfigurer.class, RETURNS_SELF);
        final var captor = ArgumentCaptor.<Customizer<OAuth2AuthorizationEndpointConfigurer>>captor();
        when(server.authorizationEndpoint(captor.capture())).thenReturn(server);
        final var endpoint = mock(OAuth2AuthorizationEndpointConfigurer.class, RETURNS_SELF);
        final var convertersCaptor = ArgumentCaptor.<Consumer<List<AuthenticationConverter>>>captor();
        when(endpoint.authorizationRequestConverters(convertersCaptor.capture())).thenReturn(endpoint);
        final var providersCaptor = ArgumentCaptor.<Consumer<List<AuthenticationProvider>>>captor();
        when(endpoint.authenticationProviders(providersCaptor.capture())).thenReturn(endpoint);

        customizer.customize(server);
        captor.getValue().customize(endpoint);
        final var converters = new ArrayList<AuthenticationConverter>();
        converters.add(mock(AuthenticationConverter.class));
        convertersCaptor.getValue().accept(converters);
        final var providers = new ArrayList<AuthenticationProvider>();
        providers.add(mock(AuthenticationProvider.class));
        providersCaptor.getValue().accept(providers);

        assertEquals(converter, converters.getFirst());
        assertEquals(2, converters.size());
        assertEquals(provider, providers.getFirst());
        assertEquals(2, providers.size());
        verify(endpoint).authorizationResponseHandler(responseHandler);
    }
}
