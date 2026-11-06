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

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * Raised while an authorization request is validated when the user must present a second factor first. It is not a
 * failure to report to the client: {@link SecondFactorErrorResponseHandler} sends the user to the second-factor page
 * instead. A step-up exception ({@link #forStepUp()}) tells that the request asked for more than the sign-in policy,
 * so a remembered (trusted) device is not enough and the page must ask for a real second factor.
 */
public class SecondFactorRequiredException extends OAuth2AuthenticationException {

    /** Error code of the exception. */
    public static final String ERROR_CODE = "second_factor_required";

    /** Serial version. */
    private static final long serialVersionUID = 1L;

    /** Whether the request asked for a step-up that a remembered device cannot satisfy. */
    private final boolean stepUp;

    /**
     * Creates the exception of a sign-in that does not satisfy the policy yet.
     */
    public SecondFactorRequiredException() {
        this(false);
    }

    /**
     * Creates the exception.
     *
     * @param stepUp whether the request asked for a step-up that a remembered device cannot satisfy.
     */
    private SecondFactorRequiredException(final boolean stepUp) {
        super(new OAuth2Error(ERROR_CODE, "A second authentication factor is required", null));
        this.stepUp = stepUp;
    }

    /**
     * Creates the exception of a step-up request ({@code acr_values}) that needs a real second factor.
     *
     * @return the exception.
     */
    public static SecondFactorRequiredException forStepUp() {
        return new SecondFactorRequiredException(true);
    }

    /**
     * Tells whether the request asked for a step-up that a remembered device cannot satisfy.
     *
     * @return {@code true} for a step-up.
     */
    public boolean isStepUp() {
        return stepUp;
    }
}
