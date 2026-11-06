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
 * Raised when an authorization request asks (through {@code max_age}) for a more recent authentication than the
 * session has. It is not a failure to report to the client: {@link SecondFactorErrorResponseHandler} sends the user
 * through a new sign-in, after {@link ReauthenticationEntryPoint} discards the stale authentication.
 */
public class ReauthenticationRequiredException extends OAuth2AuthenticationException {

    /** Error code of the exception. */
    public static final String ERROR_CODE = "reauthentication_required";

    /** Serial version. */
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     */
    public ReauthenticationRequiredException() {
        super(new OAuth2Error(ERROR_CODE, "A more recent authentication is required", null));
    }
}
