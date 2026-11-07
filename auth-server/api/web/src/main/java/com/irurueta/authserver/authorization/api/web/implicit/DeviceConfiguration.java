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

import com.irurueta.authserver.authorization.api.web.ProtocolChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.ReauthenticationEntryPoint;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorErrorResponseHandler;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorRequiredEntryPoint;
import java.time.Clock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

/**
 * Installs the device authorization grant in the protocol chain. Nothing outside this feature is edited: the chain
 * applies every {@link ProtocolChainCustomizer} bean, in order.
 */
@Configuration(value = "deviceWebConfiguration", proxyBeanMethods = false)
@EnableConfigurationProperties(DeviceRateLimitProperties.class)
public class DeviceConfiguration {

    /**
     * Declares the limiter of the attempts to verify a user code.
     *
     * @param properties limits, window and bound of the tracked keys.
     * @param clock      source of the current time.
     * @return the limiter.
     */
    @Bean
    public DeviceVerificationRateLimiter deviceVerificationRateLimiter(
            final DeviceRateLimitProperties properties, final Clock clock) {
        return new DeviceVerificationRateLimiter(properties, clock);
    }

    // tag::device-protocol-customizer[]
    /**
     * Declares the customizer that enables the device endpoints. It is applied after the multi-factor and step-up
     * ones.
     *
     * @param registeredClients          finds the clients of the devices.
     * @param serverSettings             settings of the protocol endpoints, for the device authorization one.
     * @param rateLimiter                limits the attempts.
     * @param authorizationManager       applies the multi-factor policy.
     * @param secondFactorEntryPoint     entry point of the second-factor page.
     * @param reauthenticationEntryPoint entry point that forces a new sign-in.
     * @return the customizer.
     */
    @Bean
    @Order(DeviceProtocolChainCustomizer.ORDER)
    public ProtocolChainCustomizer deviceProtocolChainCustomizer(final RegisteredClientRepository registeredClients,
            final AuthorizationServerSettings serverSettings, final DeviceVerificationRateLimiter rateLimiter,
            final MfaAuthorizationManager authorizationManager,
            final SecondFactorRequiredEntryPoint secondFactorEntryPoint,
            final ReauthenticationEntryPoint reauthenticationEntryPoint) {
        final var errorHandler = new DeviceVerificationErrorHandler(
                new SecondFactorErrorResponseHandler(secondFactorEntryPoint, reauthenticationEntryPoint),
                DeviceVerificationController.VERIFICATION_PATH);
        final var approvedUrl = DeviceVerificationController.VERIFICATION_PATH + "?"
                + DeviceVerificationController.SUCCESS_PARAMETER;
        final var successHandler = new SimpleUrlAuthenticationSuccessHandler(approvedUrl);
        return new DeviceProtocolChainCustomizer(
                new DeviceClientAuthenticationConverter(serverSettings.getDeviceAuthorizationEndpoint()),
                new DeviceClientAuthenticationProvider(registeredClients),
                new DeviceVerificationRequestGuard(rateLimiter, authorizationManager), errorHandler, successHandler);
    }
    // end::device-protocol-customizer[]
}
