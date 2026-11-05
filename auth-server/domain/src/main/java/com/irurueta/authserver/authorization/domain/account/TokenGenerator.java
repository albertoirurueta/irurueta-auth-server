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

package com.irurueta.authserver.authorization.domain.account;

/**
 * Port that creates random opaque tokens and hashes them for storage.
 */
public interface TokenGenerator {

    /**
     * Creates an unguessable URL-safe token.
     *
     * @return the token.
     */
    String generate();

    /**
     * Hashes a token with a deterministic, one-way function, so a stored hash can be looked up by the presented
     * token.
     *
     * @param token the token value.
     * @return the hash.
     */
    String hash(String token);
}
