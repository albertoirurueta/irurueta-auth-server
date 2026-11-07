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
package com.irurueta.authserver.authorization.api.web.implicit;

import java.time.Duration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * Raised while a device verification request is converted when its client address or user made too many attempts. The
 * error handler of the endpoint answers {@code 429} with a {@code Retry-After} header instead of the framework's
 * usual {@code 400}.
 */
public class DeviceVerificationRateLimitedException extends OAuth2AuthenticationException {

    /** Error code of the exception. */
    public static final String ERROR_CODE = "too_many_attempts";

    /** Serial version. */
    private static final long serialVersionUID = 1L;

    /** How long until the window ends and the attempts are accepted again. */
    private final Duration retryAfter;

    /**
     * Creates the exception.
     *
     * @param retryAfter how long until the attempts are accepted again.
     */
    public DeviceVerificationRateLimitedException(final Duration retryAfter) {
        super(new OAuth2Error(ERROR_CODE, "Too many attempts to verify a user code", null));
        this.retryAfter = retryAfter;
    }

    /**
     * Tells how long until the attempts are accepted again.
     *
     * @return the time to wait.
     */
    public Duration retryAfter() {
        return retryAfter;
    }
}
