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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.ReauthenticationEntryPoint;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorRequiredEntryPoint;
import java.time.Clock;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * Unit tests of {@link DeviceConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class DeviceConfigurationTest {

    /** Finds the clients of the devices. */
    @Mock
    private RegisteredClientRepository registeredClients;

    /** Finds the device authorization of a user code. */
    @Mock
    private OAuth2AuthorizationService authorizationService;

    /** Applies the multi-factor policy. */
    @Mock
    private MfaAuthorizationManager authorizationManager;

    /** Entry point of the second-factor page. */
    @Mock
    private SecondFactorRequiredEntryPoint secondFactorEntryPoint;

    /** Entry point that forces a new sign-in. */
    @Mock
    private ReauthenticationEntryPoint reauthenticationEntryPoint;

    /** Configuration under test. */
    private final DeviceConfiguration configuration = new DeviceConfiguration();

    /**
     * Verifies that the limiter is built from the settings.
     */
    @Test
    void deviceVerificationRateLimiter_whenCalled_buildsTheLimiter() {
        final var properties = new DeviceRateLimitProperties(true, Duration.ofMinutes(1), 1, 1, 1);

        assertNotNull(configuration.deviceVerificationRateLimiter(properties, Clock.systemUTC()));
    }

    /**
     * Verifies that the customizer is a {@link DeviceProtocolChainCustomizer} declared with its order.
     *
     * @throws NoSuchMethodException if the bean method is missing.
     */
    @Test
    void deviceProtocolChainCustomizer_whenCalled_buildsTheCustomizerWithItsOrder() throws NoSuchMethodException {
        final var limiter = new DeviceVerificationRateLimiter(
                new DeviceRateLimitProperties(true, Duration.ofMinutes(1), 1, 1, 1), Clock.systemUTC());

        final var customizer = configuration.deviceProtocolChainCustomizer(registeredClients,
                authorizationService, AuthorizationServerSettings.builder().build(), limiter, authorizationManager,
                secondFactorEntryPoint, reauthenticationEntryPoint);

        assertInstanceOf(DeviceProtocolChainCustomizer.class, customizer);
        final var method = DeviceConfiguration.class.getMethod("deviceProtocolChainCustomizer",
                RegisteredClientRepository.class, OAuth2AuthorizationService.class, AuthorizationServerSettings.class,
                DeviceVerificationRateLimiter.class, MfaAuthorizationManager.class,
                SecondFactorRequiredEntryPoint.class, ReauthenticationEntryPoint.class);
        assertEquals(DeviceProtocolChainCustomizer.ORDER, method.getAnnotation(Order.class).value());
    }
}
