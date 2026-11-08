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

package com.irurueta.authserver.authorization.api.web.par;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;

/**
 * Unit tests of {@link ParConfiguration}.
 */
class ParConfigurationTest {

    /** Expected order of the customizer. */
    private static final int EXPECTED_ORDER = 5;

    /** Subject under test. */
    private final ParConfiguration configuration = new ParConfiguration();

    /**
     * The configuration only exists when the property is {@code true}.
     */
    @Test
    void parConfiguration_always_isConditionalOnTheEnabledProperty() {
        final var condition = ParConfiguration.class.getAnnotation(ConditionalOnProperty.class);

        assertNotNull(condition);
        assertEquals("authserver.par", condition.prefix());
        assertEquals("enabled", condition.name()[0]);
        assertEquals("true", condition.havingValue());
    }

    /**
     * The customizer is ordered after the client authentication and legacy implicit ones.
     *
     * @throws NoSuchMethodException if the bean method does not exist.
     */
    @Test
    void parProtocolChainCustomizer_always_hasOrderFive() throws NoSuchMethodException {
        final var method = ParConfiguration.class.getMethod("parProtocolChainCustomizer");

        assertEquals(EXPECTED_ORDER, ParConfiguration.ORDER);
        assertEquals(EXPECTED_ORDER, method.getAnnotation(Order.class).value());
    }

    /**
     * The customizer enables the pushed authorization request endpoint.
     */
    @Test
    void customize_always_enablesThePushedAuthorizationRequestEndpoint() {
        final var server = mock(OAuth2AuthorizationServerConfigurer.class);

        configuration.parProtocolChainCustomizer().customize(server);

        verify(server).pushedAuthorizationRequestEndpoint(any(Customizer.class));
    }
}
