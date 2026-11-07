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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.PhonePageApi;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Keeps the phone page and its form posts behind the multi-factor policy, as the passkeys page is: a session that only
 * presented the password of an account that still has to complete its second factor is sent to the second-factor page
 * instead of being able to change the phone that receives the codes.
 */
@RequiredArgsConstructor
public class PhonePageChainCustomizer implements LoginChainCustomizer {

    /** Order of this customizer in the login chain, after the one-time token one ({@code 3}). */
    public static final int ORDER = 4;

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
                .requestMatchers(PhonePageApi.PATH_PHONE_PAGE, PhonePageApi.PATH_PHONE_PAGE + "/**")
                .access(authorizationManager));
    }
}
