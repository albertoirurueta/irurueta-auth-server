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
package com.irurueta.authserver.authorization.api.web.mfa;

import java.time.Duration;

/**
 * Thrown by {@link StepUpGuard} when the bearer token of an API call does not show a recent enough multi-factor
 * sign-in for the operation. {@link MfaExceptionHandler} answers it as RFC 9470 describes: {@code 401} with
 * {@code WWW-Authenticate: Bearer error="insufficient_user_authentication"} and the {@code acr_values} and
 * {@code max_age} the client must ask for.
 */
public class InsufficientUserAuthenticationException extends RuntimeException {

    /** Serialization version. */
    private static final long serialVersionUID = 1L;

    /** Authentication context class the operation requires. */
    private final String acrValues;

    /** Maximum age of the sign-in the operation accepts. */
    private final Duration maxAge;

    /**
     * Creates the exception.
     *
     * @param acrValues authentication context class the operation requires.
     * @param maxAge    maximum age of the sign-in the operation accepts.
     */
    public InsufficientUserAuthenticationException(final String acrValues, final Duration maxAge) {
        super("A multi-factor sign-in within the last " + maxAge.toSeconds() + " seconds is required");
        this.acrValues = acrValues;
        this.maxAge = maxAge;
    }

    /**
     * Gets the authentication context class the operation requires.
     *
     * @return the value for the {@code acr_values} parameter.
     */
    public String getAcrValues() {
        return acrValues;
    }

    /**
     * Gets the maximum age of the sign-in the operation accepts.
     *
     * @return the maximum age.
     */
    public Duration getMaxAge() {
        return maxAge;
    }
}
