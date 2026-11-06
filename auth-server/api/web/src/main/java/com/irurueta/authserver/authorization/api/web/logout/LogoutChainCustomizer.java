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

package com.irurueta.authserver.authorization.api.web.logout;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

/**
 * Configures how a user signs out of the login/UI chain: a POST to {@value #LOGOUT_PATH} (protected by CSRF, so a
 * third-party page cannot sign the user out) invalidates the session, deletes its cookie and returns to the login
 * page.
 */
@Component
@Order(10)
public class LogoutChainCustomizer implements LoginChainCustomizer {

    /** Path of the logout endpoint, and of the confirmation page it is reached from. */
    public static final String LOGOUT_PATH = "/logout";

    /** Where the user lands after signing out. */
    public static final String LOGOUT_SUCCESS_URL = "/login?logout";

    /** Name of the session cookie. */
    public static final String SESSION_COOKIE = "JSESSIONID";

    // tag::logout-config[]
    @Override
    public void customize(final HttpSecurity http) {
        http.logout(logout -> logout
                .logoutUrl(LOGOUT_PATH)
                .logoutSuccessUrl(LOGOUT_SUCCESS_URL)
                .invalidateHttpSession(true)
                .deleteCookies(SESSION_COOKIE));
    }
    // end::logout-config[]
}
