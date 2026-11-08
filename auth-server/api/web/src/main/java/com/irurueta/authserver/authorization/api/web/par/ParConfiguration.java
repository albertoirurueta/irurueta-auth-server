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

import com.irurueta.authserver.authorization.api.web.ProtocolChainCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;

/**
 * Enables pushed authorization requests (RFC 9126) when {@code authserver.par.enabled} is {@code true}: a client
 * authenticates at {@code POST /oauth2/par}, receives a one-time {@code request_uri} and then sends the user to the
 * authorization endpoint with it. The authorization endpoint's converters, the multi-factor policy and the step-up
 * rules apply to the request exactly as they do to one sent in the query. Without the property no bean is created, the
 * endpoint does not exist and the metadata does not advertise it.
 */
@Configuration(value = "parWebConfiguration", proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "authserver.par", name = "enabled", havingValue = "true")
public class ParConfiguration {

    /** Order of the customizer: after the client authentication ({@code 3}) and legacy implicit ({@code 4}) ones. */
    public static final int ORDER = 5;

    // tag::par-chain[]
    /**
     * Declares the customizer that enables the pushed authorization request endpoint.
     *
     * @return the customizer.
     */
    @Bean
    @Order(ORDER)
    public ProtocolChainCustomizer parProtocolChainCustomizer() {
        return server -> server.pushedAuthorizationRequestEndpoint(Customizer.withDefaults());
    }
    // end::par-chain[]
}
