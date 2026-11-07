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
package com.irurueta.authserver.authorization.domain.ott;

/**
 * Port that hashes one-time codes so that only the hash is stored.
 */
public interface OneTimeCodeHasher {

    /**
     * Hashes a code.
     *
     * @param code the code.
     * @return the hash.
     */
    String hash(String code);

    /**
     * Tells whether a code matches a hash, comparing in constant time.
     *
     * @param code the submitted code.
     * @param hash the stored hash.
     * @return {@code true} when the code produces the hash.
     */
    boolean matches(String code, String hash);
}
