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
package com.irurueta.authserver.authorization.api.web.social;

import com.irurueta.authserver.authorization.api.web.ProblemJsonExceptionHandler;
import com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException;
import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.domain.social.LastSignInMethodException;
import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 * Base of the exception handlers of the APIs that remove a sign-in method of the account (the linked identities, the
 * bound certificates): both refuse to remove the last way to sign in and both need a recent multi-factor sign-in, so
 * both answer those failures the same way. The step-up challenge is the one the rest of the account API gives
 * ({@link MfaExceptionHandler}), so a client handles the same {@code 401} everywhere. Each subclass is the
 * {@code @RestControllerAdvice} of its own API and names the base of its problem types.
 */
public abstract class SignInMethodExceptionHandler extends ProblemJsonExceptionHandler {

    /** Base of the problem type URNs of the API, for example {@code urn:problem:identity:}. */
    private final String typeBase;

    /** Builds the step-up challenge. */
    private final MfaExceptionHandler mfaExceptionHandler;

    /**
     * Creates the handler.
     *
     * @param typeBase            base of the problem type URNs of the API.
     * @param mfaExceptionHandler builds the step-up challenge.
     */
    protected SignInMethodExceptionHandler(final String typeBase, final MfaExceptionHandler mfaExceptionHandler) {
        this.typeBase = typeBase;
        this.mfaExceptionHandler = mfaExceptionHandler;
    }

    /**
     * Answers a sign-in method that is the last way to sign in to the account.
     *
     * @param exception the failure.
     * @return the {@code 409} problem detail.
     */
    @ExceptionHandler(LastSignInMethodException.class)
    public ResponseEntity<ProblemDetail> handleLastSignInMethod(final LastSignInMethodException exception) {
        return respond(HttpStatus.CONFLICT, "last-sign-in-method", "Last sign-in method", exception.getMessage());
    }

    /**
     * Answers a token whose sign-in is not recent or strong enough: {@code 401} with the RFC 9470 challenge.
     *
     * @param exception the failure.
     * @return the {@code 401} problem detail with the {@code WWW-Authenticate} challenge.
     */
    @ExceptionHandler(InsufficientUserAuthenticationException.class)
    public ResponseEntity<ProblemDetail> handleInsufficientUserAuthentication(
            final InsufficientUserAuthenticationException exception) {
        return mfaExceptionHandler.handleInsufficientUserAuthentication(exception);
    }

    /**
     * Builds a problem response whose type is below the base of the API.
     *
     * @param status HTTP status.
     * @param type   last segment of the problem type.
     * @param title  short summary.
     * @param detail explanation.
     * @return the response.
     */
    protected ResponseEntity<ProblemDetail> respond(
            final HttpStatus status, final String type, final String title, final String detail) {
        final var problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create(typeBase + type));
        problem.setTitle(title);
        return problemResponse(problem);
    }
}
