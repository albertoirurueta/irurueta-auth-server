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
package com.irurueta.authserver.authorization.api.web.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link X509TlsKeyStore}.
 */
class X509TlsKeyStoreTest {

    /**
     * Verifies that the description tells where the key store is but never shows its password.
     */
    @Test
    void toString_whenDescribed_hidesThePassword() {
        final var password = UUID.randomUUID().toString();
        final var keyStore = new X509TlsKeyStore(Path.of("store.p12"), password, "PKCS12");

        final var description = keyStore.toString();

        assertTrue(description.contains("store.p12"));
        assertFalse(description.contains(password));
        assertEquals(password, keyStore.password());
    }
}
