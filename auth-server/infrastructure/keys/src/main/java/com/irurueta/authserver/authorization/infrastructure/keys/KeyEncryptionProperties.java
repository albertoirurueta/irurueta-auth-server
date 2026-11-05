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

// tag::keys-encryption[]
/**
 * Inputs of the encryption of private signing keys at rest.
 *
 * <p>The record never prints its values: a log line or an exception message that mentions it cannot leak them.
 *
 * @param password the passphrase the encryption key is derived from.
 * @param salt     the salt of the derivation, hex encoded.
 */
public record KeyEncryptionProperties(String password, String salt) {

    /**
     * Validates the properties.
     *
     * @throws IllegalArgumentException if the passphrase or the salt is null or blank.
     */
    public KeyEncryptionProperties {
        if (password == null || password.isBlank() || salt == null || salt.isBlank()) {
            throw new IllegalArgumentException("authserver.keys.encryption.password and .salt must be set");
        }
    }

    /**
     * Describes the properties without revealing them.
     *
     * @return a fixed text.
     */
    @Override
    public String toString() {
        return "KeyEncryptionProperties[redacted]";
    }
}
// end::keys-encryption[]
