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
import static org.mockito.ArgumentMatchers.any;
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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2ClientAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2DeviceAuthorizationEndpointConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2DeviceVerificationEndpointConfigurer;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Unit tests of {@link DeviceProtocolChainCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class DeviceProtocolChainCustomizerTest {

    /** The guard to install. */
    @Mock
    private AuthenticationConverter guard;

    /** Reads the public client of the device flow. */
    @Mock
    private AuthenticationConverter clientConverter;

    /** Authenticates the public client of the device flow. */
    @Mock
    private AuthenticationProvider clientProvider;

    /** Handler of the failures. */
    @Mock
    private AuthenticationFailureHandler errorHandler;

    /** Handler of the approvals. */
    @Mock
    private AuthenticationSuccessHandler successHandler;

    /**
     * Verifies that the order is after the multi-factor and step-up customizers.
     */
    @Test
    void order_isAfterTheStepUpCustomizer() {
        assertEquals(2, DeviceProtocolChainCustomizer.ORDER);
    }

    /**
     * Verifies that the device authorization endpoint is enabled.
     */
    @Test
    void customize_whenApplied_enablesTheDeviceAuthorizationEndpoint() {
        final var server = mock(OAuth2AuthorizationServerConfigurer.class, RETURNS_SELF);

        customizer().customize(server);

        verify(server).deviceAuthorizationEndpoint(any());
    }

    /**
     * Verifies that the verification endpoint hands the consent to the consent page, installs the guard before the
     * framework's converters and answers with the handlers.
     */
    @Test
    @SuppressWarnings("unchecked")
    void customize_whenApplied_configuresTheVerificationEndpoint() {
        final var server = mock(OAuth2AuthorizationServerConfigurer.class, RETURNS_SELF);
        final var captor = ArgumentCaptor.<Customizer<OAuth2DeviceVerificationEndpointConfigurer>>captor();
        when(server.deviceVerificationEndpoint(captor.capture())).thenReturn(server);
        final var endpoint = mock(OAuth2DeviceVerificationEndpointConfigurer.class, RETURNS_SELF);
        final var convertersCaptor = ArgumentCaptor.<Consumer<List<AuthenticationConverter>>>captor();
        when(endpoint.deviceVerificationRequestConverters(convertersCaptor.capture())).thenReturn(endpoint);

        customizer().customize(server);
        captor.getValue().customize(endpoint);
        final var converters = new ArrayList<AuthenticationConverter>();
        converters.add(mock(AuthenticationConverter.class));
        convertersCaptor.getValue().accept(converters);

        verify(endpoint).consentPage("/oauth2/consent");
        verify(endpoint).errorResponseHandler(errorHandler);
        verify(endpoint).deviceVerificationResponseHandler(successHandler);
        assertEquals(guard, converters.getFirst());
        assertEquals(2, converters.size());
    }

    /**
     * Verifies that the public client of the device flow is authenticated by its identifier.
     */
    @Test
    void customize_whenApplied_addsTheDeviceClientAuthentication() {
        final var server = mock(OAuth2AuthorizationServerConfigurer.class, RETURNS_SELF);
        final var captor = ArgumentCaptor.<Customizer<OAuth2ClientAuthenticationConfigurer>>captor();
        when(server.clientAuthentication(captor.capture())).thenReturn(server);
        final var client = mock(OAuth2ClientAuthenticationConfigurer.class, RETURNS_SELF);

        customizer().customize(server);
        captor.getValue().customize(client);

        verify(client).authenticationConverter(clientConverter);
        verify(client).authenticationProvider(clientProvider);
    }

    /**
     * Keeps the type of the device authorization configurer referenced, the one the customizer enables.
     */
    @Test
    void customize_whenApplied_usesTheDefaultsOfTheDeviceAuthorizationEndpoint() {
        final var server = mock(OAuth2AuthorizationServerConfigurer.class, RETURNS_SELF);
        final var captor = ArgumentCaptor.<Customizer<OAuth2DeviceAuthorizationEndpointConfigurer>>captor();
        when(server.deviceAuthorizationEndpoint(captor.capture())).thenReturn(server);

        customizer().customize(server);
        captor.getValue().customize(mock(OAuth2DeviceAuthorizationEndpointConfigurer.class));

        verify(server).deviceAuthorizationEndpoint(captor.getValue());
    }

    /**
     * Builds the customizer.
     *
     * @return the customizer.
     */
    private DeviceProtocolChainCustomizer customizer() {
        return new DeviceProtocolChainCustomizer(clientConverter, clientProvider, guard, errorHandler,
                successHandler);
    }
}
