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

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Builds throw-away key-encryption inputs at test run time, so no secret-looking literal lives in the sources.
 */
final class KeyTestSupport {

    /** Number of random bytes of the salt. */
    private static final int SALT_BYTES = 16;

    /**
     * Not instantiable.
     */
    private KeyTestSupport() {
    }

    /**
     * Creates random key-encryption inputs.
     *
     * @return the inputs.
     */
    static KeyEncryptionProperties randomProperties() {
        final var salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        return new KeyEncryptionProperties(UUID.randomUUID().toString(), HexFormat.of().formatHex(salt));
    }
}
