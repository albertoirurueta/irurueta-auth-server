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

package com.irurueta.authserver.authorization.infrastructure.keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Reads the key-encryption inputs from configuration ({@code authserver.keys.encryption.password} and
 * {@code authserver.keys.encryption.salt}, taken from the environment in production). Without them the application
 * does not start. The {@code dev} profile uses {@link DevKeyEncryptionSecret} instead.
 */
@Configuration(proxyBeanMethods = false)
@Profile("!dev")
public class KeyEncryptionConfiguration {

    /**
     * Creates the key-encryption inputs.
     *
     * @param password the configured passphrase.
     * @param salt     the configured hex-encoded salt.
     * @return the inputs.
     */
    @Bean
    public KeyEncryptionProperties keyEncryptionProperties(
            @Value("${authserver.keys.encryption.password}") final String password,
            @Value("${authserver.keys.encryption.salt}") final String salt) {
        return new KeyEncryptionProperties(password, salt);
    }
}
