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
package com.irurueta.authserver.authorization.domain.totp;

/**
 * Port that protects TOTP secrets at rest.
 */
public interface TotpSecretCipher {

    /**
     * Encrypts a secret.
     *
     * @param secret the clear secret.
     * @return the encrypted form, which includes whatever is needed to decrypt it.
     */
    byte[] encrypt(byte[] secret);

    /**
     * Decrypts a secret.
     *
     * @param encrypted a value produced by {@link #encrypt(byte[])}.
     * @return the clear secret.
     * @throws IllegalStateException if the value was not produced by this cipher or was tampered with.
     */
    byte[] decrypt(byte[] encrypted);
}
