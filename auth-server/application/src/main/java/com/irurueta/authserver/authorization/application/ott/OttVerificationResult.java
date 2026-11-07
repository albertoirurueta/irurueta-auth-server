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

package com.irurueta.authserver.authorization.application.ott;

import com.irurueta.authserver.authorization.domain.ott.OttChannel;

/**
 * Outcome of the verification of a one-time code.
 *
 * @param status  what happened.
 * @param channel the channel the accepted code was delivered through; {@code null} unless the code was accepted.
 */
public record OttVerificationResult(Status status, OttChannel channel) {

    /** Result of a wrong, expired, burnt or already used code. */
    private static final OttVerificationResult FAILURE = new OttVerificationResult(Status.FAILURE, null);

    /** Result when the second factor of the user is locked. */
    private static final OttVerificationResult LOCKED = new OttVerificationResult(Status.LOCKED, null);

    /**
     * Creates the result of an accepted code.
     *
     * @param channel the channel of the code.
     * @return the result.
     */
    public static OttVerificationResult success(final OttChannel channel) {
        return new OttVerificationResult(Status.SUCCESS, channel);
    }

    /**
     * Returns the result of a rejected code.
     *
     * @return the result.
     */
    public static OttVerificationResult failure() {
        return FAILURE;
    }

    /**
     * Returns the result of a locked second factor.
     *
     * @return the result.
     */
    public static OttVerificationResult locked() {
        return LOCKED;
    }

    /**
     * Tells whether the code was accepted.
     *
     * @return {@code true} for {@link Status#SUCCESS}.
     */
    public boolean isSuccess() {
        return status == Status.SUCCESS;
    }

    /** What happened when a code was verified. */
    public enum Status {

        /** The code was valid and has been consumed. */
        SUCCESS,

        /** The code was wrong, expired, burnt or already used. */
        FAILURE,

        /** The second factor of the user is locked after too many failures. */
        LOCKED
    }
}
