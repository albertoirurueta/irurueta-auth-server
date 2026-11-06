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


package com.irurueta.authserver.authorization.api.web.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationEndpointConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * Unit tests of {@link StepUpProtocolChainCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class StepUpProtocolChainCustomizerTest {

    /** Converter to install. */
    @Mock
    private AuthenticationConverter stepUpConverter;

    /**
     * Verifies that the converter is installed before the framework's ones.
     */
    @Test
    @SuppressWarnings("unchecked")
    void customize_whenApplied_installsConverterFirst() {
        final var server = mock(OAuth2AuthorizationServerConfigurer.class);
        final var endpoint = mock(OAuth2AuthorizationEndpointConfigurer.class);
        final var serverCaptor = ArgumentCaptor.<Customizer<OAuth2AuthorizationEndpointConfigurer>>captor();
        final var convertersCaptor = ArgumentCaptor.<Consumer<List<AuthenticationConverter>>>captor();
        when(server.authorizationEndpoint(serverCaptor.capture())).thenReturn(server);
        when(endpoint.authorizationRequestConverters(convertersCaptor.capture())).thenReturn(endpoint);

        new StepUpProtocolChainCustomizer(stepUpConverter).customize(server);
        serverCaptor.getValue().customize(endpoint);
        final var converters = new ArrayList<AuthenticationConverter>();
        converters.add(mock(AuthenticationConverter.class));
        convertersCaptor.getValue().accept(converters);

        verify(server).authorizationEndpoint(serverCaptor.getValue());
        assertEquals(stepUpConverter, converters.getFirst());
        assertEquals(2, converters.size());
    }
}
