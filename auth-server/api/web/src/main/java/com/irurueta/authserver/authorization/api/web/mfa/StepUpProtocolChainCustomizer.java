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

import com.irurueta.authserver.authorization.api.web.ProtocolChainCustomizer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * Applies step-up authentication ({@code acr_values} and {@code max_age}) to {@code /oauth2/authorize}. It adds a
 * {@link StepUpAuthorizationRequestConverter} before the framework's converters, so it does not touch the
 * authentication validator installed by {@link MfaProtocolChainCustomizer} (a validator is a setter: the last one
 * installed would win). Its refusals are answered by the endpoint's {@link SecondFactorErrorResponseHandler}.
 */
@RequiredArgsConstructor
public class StepUpProtocolChainCustomizer implements ProtocolChainCustomizer {

    /** Converter that vetoes the requests whose step-up parameters the session does not satisfy. */
    private final AuthenticationConverter stepUpConverter;

    /**
     * Customizes the authorization endpoint.
     *
     * @param server configurer of the authorization server.
     */
    @Override
    public void customize(final OAuth2AuthorizationServerConfigurer server) {
        server.authorizationEndpoint(endpoint -> endpoint
                .authorizationRequestConverters(converters -> converters.addFirst(stepUpConverter)));
    }
}
