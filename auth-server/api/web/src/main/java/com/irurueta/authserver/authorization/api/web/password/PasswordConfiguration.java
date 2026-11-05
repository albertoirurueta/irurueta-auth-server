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

package com.irurueta.authserver.authorization.api.web.password;

import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

/**
 * Registers the password encoder of the password-based sign-in and of the client secrets: new values are encoded with
 * Argon2, while bcrypt and PBKDF2 hashes stay verifiable (and are upgraded on the next successful sign-in).
 */
@Configuration(proxyBeanMethods = false)
public class PasswordConfiguration {

    /** Identifier (stored as {@code {id}} prefix) of the algorithm used to encode new passwords. */
    public static final String DEFAULT_ENCODING_ID = "argon2@SpringSecurity_v5_8";

    /** Identifier of the legacy bcrypt encoding. */
    public static final String BCRYPT_ENCODING_ID = "bcrypt";

    /** Identifier of the legacy PBKDF2 encoding. */
    public static final String PBKDF2_ENCODING_ID = "pbkdf2@SpringSecurity_v5_8";

    // tag::password-encoder[]
    /**
     * Creates the password encoder: a delegating encoder whose default is Argon2, with bcrypt and PBKDF2 kept for
     * legacy hashes.
     *
     * @return the delegating password encoder.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new DelegatingPasswordEncoder(DEFAULT_ENCODING_ID, Map.of(
                DEFAULT_ENCODING_ID, Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(),
                BCRYPT_ENCODING_ID, new BCryptPasswordEncoder(),
                PBKDF2_ENCODING_ID, Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()));
    }
    // end::password-encoder[]
}
