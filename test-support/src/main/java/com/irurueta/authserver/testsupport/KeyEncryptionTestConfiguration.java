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

package com.irurueta.authserver.testsupport;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.UUID;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;

/**
 * Supplies the inputs of the encryption of signing keys at rest to a test context. The values are generated at
 * runtime for each context, so no secret-looking literal exists in the sources and nothing persists between runs.
 */
@TestConfiguration(proxyBeanMethods = false)
public class KeyEncryptionTestConfiguration {

    /** Source of the generated values. */
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Number of random bytes of the generated salt. */
    private static final int SALT_BYTES = 16;

    /**
     * Registers {@code authserver.keys.encryption.password} and {@code .salt} with random values.
     *
     * @return the registrar.
     */
    @Bean
    public DynamicPropertyRegistrar keyEncryptionPropertiesRegistrar() {
        final var salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        final var encodedSalt = HexFormat.of().formatHex(salt);
        final var passphrase = UUID.randomUUID().toString();
        return registry -> {
            registry.add("authserver.keys.encryption.password", () -> passphrase);
            registry.add("authserver.keys.encryption.salt", () -> encodedSalt);
        };
    }
}
