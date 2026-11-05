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

package com.irurueta.authserver.authorization.api.web.login;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Extension point that lets an authentication method customize the login/UI security filter chain.
 * Every bean of this type is applied to the chain in {@link org.springframework.core.annotation.Order} order.
 *
 * <p>It deliberately does not extend {@link org.springframework.security.config.Customizer}: Spring Security applies
 * every {@code Customizer<HttpSecurity>} bean to <em>every</em> filter chain, not only to the login chain.
 */
@FunctionalInterface
public interface LoginChainCustomizer {

    /**
     * Customizes the login/UI chain.
     *
     * @param http security builder of the chain.
     */
    void customize(HttpSecurity http);
}
