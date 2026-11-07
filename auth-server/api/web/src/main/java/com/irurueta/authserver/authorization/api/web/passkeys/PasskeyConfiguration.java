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

package com.irurueta.authserver.authorization.api.web.passkeys;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.application.passkeys.PasskeyProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Installs the passkeys (WebAuthn) in the login/UI chain. Nothing outside this feature is edited: the chain applies
 * every {@link LoginChainCustomizer} bean, in order, before its catch-all rule.
 */
@Configuration(value = "passkeyWebConfiguration", proxyBeanMethods = false)
public class PasskeyConfiguration {

    // tag::passkeys-chain-customizer[]
    /**
     * Declares the customizer that enables {@code http.webAuthn(...)}, permits its public endpoints, keeps the
     * registration endpoints behind the multi-factor policy and removes the ones that would bypass the step-up. It is
     * applied after the TOTP customizer.
     *
     * @param properties           relying party settings.
     * @param authorizationManager applies the multi-factor policy.
     * @param userDetailsService   loads the account of the user a passkey belongs to.
     * @return the customizer.
     */
    @Bean
    @Order(PasskeyChainCustomizer.ORDER)
    public LoginChainCustomizer passkeyChainCustomizer(final PasskeyProperties properties,
            final MfaAuthorizationManager authorizationManager, final UserDetailsService userDetailsService) {
        return new PasskeyChainCustomizer(properties, authorizationManager, userDetailsService);
    }
    // end::passkeys-chain-customizer[]
}
