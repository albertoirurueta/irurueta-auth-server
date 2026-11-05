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

package com.irurueta.authserver.authorization.api.web.account;

import java.time.Duration;

/**
 * A client address or an e-mail address made more account requests than its window allows. It is answered with
 * {@code 429 Too Many Requests}.
 */
public class AccountRateLimitExceededException extends RuntimeException {

    /** Serialization version. */
    private static final long serialVersionUID = 1L;

    /** How long until the window ends and requests are accepted again. */
    private final Duration retryAfter;

    /**
     * Creates the exception.
     *
     * @param retryAfter how long until requests are accepted again.
     */
    public AccountRateLimitExceededException(final Duration retryAfter) {
        super("Too many account requests; try again later");
        this.retryAfter = retryAfter;
    }

    /**
     * Returns how long until requests are accepted again.
     *
     * @return the remaining time of the window.
     */
    public Duration getRetryAfter() {
        return retryAfter;
    }
}
