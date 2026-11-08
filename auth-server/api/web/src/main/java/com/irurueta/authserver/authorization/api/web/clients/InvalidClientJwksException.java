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

package com.irurueta.authserver.authorization.api.web.clients;

/**
 * Raised when the public JWK set of a client is not a valid JWK set, is empty or holds a key with private material.
 * It is answered as {@code 400 invalid-jwks}.
 */
public class InvalidClientJwksException extends RuntimeException {

    /** Serialization version. */
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message what is wrong with the JWK set; it never contains key material.
     */
    public InvalidClientJwksException(final String message) {
        super(message);
    }

    /**
     * Creates the exception with a cause.
     *
     * @param message what is wrong with the JWK set; it never contains key material.
     * @param cause   the parsing failure.
     */
    public InvalidClientJwksException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
