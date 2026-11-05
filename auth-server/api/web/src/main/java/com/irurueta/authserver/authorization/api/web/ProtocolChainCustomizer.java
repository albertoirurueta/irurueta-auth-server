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
package com.irurueta.authserver.authorization.api.web;

import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;

/**
 * Extension point that lets a feature customize the OAuth 2.1 / OpenID Connect protocol endpoints, for example to
 * add an authentication provider or a converter to the token endpoint. Every bean of this type is applied to the
 * protocol filter chain in {@link org.springframework.core.annotation.Order} order.
 *
 * <p>It deliberately does not extend {@link org.springframework.security.config.Customizer}: Spring Security applies
 * every {@code Customizer<OAuth2AuthorizationServerConfigurer>} bean to <em>every</em> {@code HttpSecurity}, which
 * would turn the login and API chains into protocol chains.
 */
@FunctionalInterface
public interface ProtocolChainCustomizer {

    /**
     * Customizes the protocol endpoints.
     *
     * @param server configurer of the authorization server.
     */
    void customize(OAuth2AuthorizationServerConfigurer server);
}
