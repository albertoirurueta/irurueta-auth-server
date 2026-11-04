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

package com.irurueta.authserver.authorization.password;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Registers the password-based user store and its password encoder.
 */
@Configuration(proxyBeanMethods = false)
public class PasswordConfiguration {

    /**
     * Creates the user details service backed by the database.
     *
     * @param jdbcTemplate JDBC template of the application datasource.
     * @return the user details service.
     */
    @Bean
    public UserDetailsService userDetailsService(final JdbcTemplate jdbcTemplate) {
        return new JdbcUserDetailsService(jdbcTemplate);
    }

    /**
     * Creates the password encoder.
     *
     * @return the delegating password encoder.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // TEMPORARY: replaced in #2
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
