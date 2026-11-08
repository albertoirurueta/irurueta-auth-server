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
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

// tag::implicit-chain[]
/**
 * Adds the legacy implicit flow to the authorization endpoint: its converter first, its provider first and its
 * response handler in place of the framework's (which it delegates to for an authorization code).
 */
@RequiredArgsConstructor
public class LegacyImplicitProtocolChainCustomizer implements ProtocolChainCustomizer {

    /** Order of the customizer, after the client authentication one ({@code 3}). */
    public static final int ORDER = 4;

    /** Reads a request with {@code response_type=token}. */
    private final AuthenticationConverter converter;

    /** Grants the request. */
    private final AuthenticationProvider provider;

    /** Redirects with the token in the fragment. */
    private final AuthenticationSuccessHandler responseHandler;

    /**
     * Customizes the authorization endpoint.
     *
     * @param server configurer of the authorization server.
     */
    @Override
    public void customize(final OAuth2AuthorizationServerConfigurer server) {
        server.authorizationEndpoint(endpoint -> endpoint
                .authorizationRequestConverters(converters -> converters.addFirst(converter))
                .authenticationProviders(providers -> providers.addFirst(provider))
                .authorizationResponseHandler(responseHandler));
    }
}
// end::implicit-chain[]
