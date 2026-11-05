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

package com.irurueta.authserver.authorization.api.web.clients;

import com.irurueta.authserver.authorization.api.web.ProtocolChainCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;

/**
 * Enables the OpenID Connect dynamic client registration endpoint ({@code /connect/register}) when
 * {@code authserver.oidc.client-registration.enabled=true}. It is off by default. The endpoint requires an initial
 * access token with scope {@code client.create}.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "authserver.oidc.client-registration", name = "enabled", havingValue = "true")
public class DynamicClientRegistrationConfiguration {

    // tag::clients-dynamic-registration[]
    /**
     * Creates the customizer that turns on the client registration endpoint of the protocol chain.
     *
     * @return the customizer.
     */
    @Bean
    public ProtocolChainCustomizer clientRegistrationProtocolChainCustomizer() {
        return server -> server.oidc(oidc -> oidc.clientRegistrationEndpoint(Customizer.withDefaults()));
    }
    // end::clients-dynamic-registration[]
}
