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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;

/**
 * Development only ({@code dev} profile): opens the SMS inbox page to everybody in the login chain, so an end-to-end
 * test can read the codes the logging sender recorded without signing in. Nothing here exists in any other profile.
 */
@Configuration(proxyBeanMethods = false)
@Profile("dev")
public class DevSmsInboxConfiguration {

    /** Order of the customizer in the login chain, after the one-time token one. */
    public static final int ORDER = OttChainCustomizer.ORDER + 1;

    /**
     * Permits the inbox page.
     *
     * @return the customizer.
     */
    @Bean
    @Order(ORDER)
    public LoginChainCustomizer devSmsInboxChainCustomizer() {
        return http -> http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(DevSmsInboxController.DEV_SMS_INBOX_PATH).permitAll());
    }
}
