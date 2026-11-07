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
import com.irurueta.authserver.authorization.api.web.consent.ConsentController;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

// tag::device-protocol-chain[]
/**
 * Enables the OAuth 2.0 Device Authorization Grant on the protocol chain. The device authorization endpoint
 * ({@code POST /oauth2/device_authorization}) is where the device, authenticated as a public client by its identifier
 * alone, obtains a device code and a user code. The verification endpoint ({@code /oauth2/device_verification}) is
 * where the signed-in user approves the device; its verification URI is the framework's default, the issuer plus the
 * endpoint, whose {@code GET} without a code is the page of {@link DeviceVerificationController}. The verification
 * endpoint is customized to guard its requests ({@link DeviceVerificationRequestGuard}), to hand the consent decision
 * to the existing consent page, to answer its failures with {@link DeviceVerificationErrorHandler} and to go back to
 * the verification page when the device was approved.
 */
@RequiredArgsConstructor
public class DeviceProtocolChainCustomizer implements ProtocolChainCustomizer {

    /** Order of the customizer: after the multi-factor ({@code 0}) and step-up ({@code 1}) ones. */
    public static final int ORDER = 2;

    /** Reads the identifier of a public client of the device flow. */
    private final AuthenticationConverter clientConverter;

    /** Authenticates a public client of the device flow. */
    private final AuthenticationProvider clientProvider;

    /** Rate limit and multi-factor policy of the verification requests. */
    private final AuthenticationConverter guard;

    /** Answers the failures of the verification endpoint. */
    private final AuthenticationFailureHandler errorHandler;

    /** Answers a verification that did not need consent, or whose consent was given. */
    private final AuthenticationSuccessHandler successHandler;

    /**
     * Customizes the device endpoints.
     *
     * @param server configurer of the authorization server.
     */
    @Override
    public void customize(final OAuth2AuthorizationServerConfigurer server) {
        server.clientAuthentication(client -> client
                .authenticationConverter(clientConverter)
                .authenticationProvider(clientProvider));
        server.deviceAuthorizationEndpoint(Customizer.withDefaults());
        server.deviceVerificationEndpoint(endpoint -> endpoint
                .consentPage(ConsentController.CONSENT_PATH)
                .deviceVerificationRequestConverters(converters -> converters.addFirst(guard))
                .errorResponseHandler(errorHandler)
                .deviceVerificationResponseHandler(successHandler));
    }
}
// end::device-protocol-chain[]
