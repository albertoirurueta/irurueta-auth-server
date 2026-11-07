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
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.IdentitiesPageApi;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Keeps the identities page and its link post behind the multi-factor policy, as the passkeys and phone pages are: a
 * session that only presented the password of an account that still has to complete its second factor is sent to the
 * second-factor page instead of being able to add a way to sign in to the account.
 */
@RequiredArgsConstructor
public class IdentitiesPageChainCustomizer implements LoginChainCustomizer {

    /** Order of this customizer in the login chain, after the X.509 one ({@code 6}). */
    public static final int ORDER = 7;

    /** Applies the multi-factor policy. */
    private final MfaAuthorizationManager authorizationManager;

    /**
     * Customizes the login/UI chain.
     *
     * @param http security builder of the chain.
     */
    @Override
    public void customize(final HttpSecurity http) {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(IdentitiesPageApi.PATH_IDENTITIES_PAGE, IdentitiesPageApi.PATH_IDENTITIES_PAGE + "/**")
                .access(authorizationManager));
    }
}
