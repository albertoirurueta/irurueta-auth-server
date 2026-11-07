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

/**
 * Thrown when the value sent to bind a certificate is not a single PEM X.509 certificate within its validity period.
 * The message never repeats the value.
 */
public class InvalidCertificateException extends RuntimeException {

    /** Serialization version. */
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message description of the problem.
     */
    public InvalidCertificateException(final String message) {
        super(message);
    }

    /**
     * Creates the exception with its cause.
     *
     * @param message description of the problem.
     * @param cause   the failure of the parser.
     */
    public InvalidCertificateException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
