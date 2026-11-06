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

import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

/**
 * Permits the stylesheet shared by the server-rendered pages, which must load before anybody has signed in.
 */
@Component
@Order(1)
public class LoginStaticResourcesCustomizer implements LoginChainCustomizer {

    /** Path of the shared stylesheet. */
    public static final String STYLESHEET_PATH = "/css/pages.css";

    @Override
    public void customize(final HttpSecurity http) {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers(STYLESHEET_PATH).permitAll());
    }
}
