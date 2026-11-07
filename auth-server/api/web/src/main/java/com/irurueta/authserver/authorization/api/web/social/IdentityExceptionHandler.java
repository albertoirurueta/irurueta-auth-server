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
import com.irurueta.authserver.authorization.api.web.v1.generated.api.IdentitiesApi;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityNotFoundException;
import com.irurueta.authserver.authorization.domain.social.LastSignInMethodException;
import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Answers the failures of the identities API as {@code application/problem+json}. The step-up challenge is the one the
 * rest of the account API gives ({@link MfaExceptionHandler}), so a client handles the same {@code 401} everywhere.
 */
@RestControllerAdvice(assignableTypes = IdentitiesApi.class)
@RequiredArgsConstructor
public class IdentityExceptionHandler extends ProblemJsonExceptionHandler {

    /** Base of the problem type URNs. */
    private static final String TYPE_BASE = "urn:problem:identity:";

    /** Builds the step-up challenge. */
    private final MfaExceptionHandler mfaExceptionHandler;

    /**
     * Answers an identity the account does not have (another account's identity is answered the same way).
     *
     * @param exception the failure.
     * @return the {@code 404} problem detail.
     */
    @ExceptionHandler(FederatedIdentityNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(final FederatedIdentityNotFoundException exception) {
        return respond(HttpStatus.NOT_FOUND, "identity-not-found", "Identity not found", exception.getMessage());
    }

    /**
     * Answers an identity that is the last way to sign in to the account.
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
     * Builds a problem response.
     *
     * @param status HTTP status.
     * @param type   last segment of the problem type.
     * @param title  short summary.
     * @param detail explanation.
     * @return the response.
     */
    private static ResponseEntity<ProblemDetail> respond(
            final HttpStatus status, final String type, final String title, final String detail) {
        final var problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create(TYPE_BASE + type));
        problem.setTitle(title);
        return problemResponse(problem);
    }
}
