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
package com.irurueta.authserver.bff.domain.documents;

import java.time.Duration;
import java.util.Optional;

/**
 * The resource server refused the operation because the access token of the session does not prove a strong or
 * recent enough authentication (RFC 9470 step-up). The user has to sign in again asking the authorization server for
 * the authentication context classes and maximum age the resource server named.
 */
public class DocumentsStepUpRequiredException extends RuntimeException {

    /** Serialization version. */
    private static final long serialVersionUID = 1L;

    /** Space-separated authentication context class references asked for, or {@code null} when none was named. */
    private final String acrValues;

    /** Maximum age of the authentication accepted, or {@code null} when none was named. */
    private final Duration maxAge;

    /**
     * Creates the exception.
     *
     * @param message   description of the failure; it never carries a token.
     * @param acrValues space-separated authentication context class references asked for, or {@code null} when the
     *                  resource server named none.
     * @param maxAge    maximum age of the authentication accepted, or {@code null} when the resource server named none.
     * @param cause     the failure that was reported, or {@code null} when there is none.
     */
    public DocumentsStepUpRequiredException(final String message, final String acrValues, final Duration maxAge,
            final Throwable cause) {
        super(message, cause);
        this.acrValues = acrValues;
        this.maxAge = maxAge;
    }

    /**
     * Returns the authentication context class references the resource server asked for.
     *
     * @return the space-separated values, or empty when the resource server named none.
     */
    public Optional<String> getAcrValues() {
        return Optional.ofNullable(acrValues);
    }

    /**
     * Returns the maximum age of the authentication the resource server accepts.
     *
     * @return the maximum age, or empty when the resource server named none.
     */
    public Optional<Duration> getMaxAge() {
        return Optional.ofNullable(maxAge);
    }
}
