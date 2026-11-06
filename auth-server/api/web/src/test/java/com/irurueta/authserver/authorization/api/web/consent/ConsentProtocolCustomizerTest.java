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

package com.irurueta.authserver.authorization.api.web.consent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationEndpointConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;

/**
 * Unit tests of {@link ConsentProtocolCustomizer}.
 */
class ConsentProtocolCustomizerTest {

    /**
     * Verifies that the authorization endpoint is pointed at the custom consent page.
     */
    @Test
    void customize_whenApplied_setsTheConsentPage() {
        final var server = mock(OAuth2AuthorizationServerConfigurer.class);
        final var captor = ArgumentCaptor.<Customizer<OAuth2AuthorizationEndpointConfigurer>>captor();

        new ConsentProtocolCustomizer().customize(server);

        verify(server).authorizationEndpoint(captor.capture());
        final var endpoint = mock(OAuth2AuthorizationEndpointConfigurer.class);
        captor.getValue().customize(endpoint);
        verify(endpoint).consentPage("/oauth2/consent");
        assertEquals("/oauth2/consent", ConsentController.CONSENT_PATH);
    }
}
