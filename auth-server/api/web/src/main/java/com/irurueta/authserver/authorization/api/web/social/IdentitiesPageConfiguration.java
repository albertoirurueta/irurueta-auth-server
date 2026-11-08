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
package com.irurueta.authserver.authorization.api.web.social;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

/**
 * Declares the chain customizer of the identities page. Unlike the rest of the social login, it does not depend on a
 * provider being configured: the page and its contract exist either way.
 */
@Configuration(proxyBeanMethods = false)
public class IdentitiesPageConfiguration {

    /**
     * Declares the customizer that keeps the identities page behind the multi-factor policy.
     *
     * @param authorizationManager applies the multi-factor policy.
     * @return the customizer.
     */
    @Bean
    @Order(IdentitiesPageChainCustomizer.ORDER)
    public LoginChainCustomizer identitiesPageChainCustomizer(final MfaAuthorizationManager authorizationManager) {
        return new IdentitiesPageChainCustomizer(authorizationManager);
    }
}
