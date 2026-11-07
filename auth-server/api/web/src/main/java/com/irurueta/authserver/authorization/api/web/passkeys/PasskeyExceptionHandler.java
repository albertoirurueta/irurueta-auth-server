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

package com.irurueta.authserver.authorization.api.web.passkeys;

import com.irurueta.authserver.authorization.api.web.ProblemJsonExceptionHandler;
import com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException;
import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.PasskeysApi;
import com.irurueta.authserver.authorization.domain.passkeys.InvalidPasskeyLabelException;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyNotFoundException;
import jakarta.validation.ConstraintViolationException;
import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Answers the failures of the passkeys API as {@code application/problem+json}. The step-up challenge is the one the
 * rest of the account API gives ({@link MfaExceptionHandler}, whose scope is the TOTP, recovery code and trusted
 * device interfaces), so a client handles the same {@code 401} everywhere.
 */
@RestControllerAdvice(assignableTypes = PasskeysApi.class)
@RequiredArgsConstructor
public class PasskeyExceptionHandler extends ProblemJsonExceptionHandler {

    /** Base of the problem type URNs. */
    private static final String TYPE_BASE = "urn:problem:passkeys:";

    /** Builds the step-up challenge. */
    private final MfaExceptionHandler mfaExceptionHandler;

    /**
     * Answers a passkey the account does not have (another account's passkey is answered the same way).
     *
     * @param exception the failure.
     * @return the {@code 404} problem detail.
     */
    @ExceptionHandler(PasskeyNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(final PasskeyNotFoundException exception) {
        return respond(HttpStatus.NOT_FOUND, "passkey-not-found", "Passkey not found", exception.getMessage());
    }

    /**
     * Answers a label the use case refuses (blank, or too long once trimmed). Only that domain exception is answered
     * as a {@code 400}: any other {@link IllegalArgumentException} is a programming error and stays a {@code 500}.
     *
     * @param exception the failure.
     * @return the {@code 400} problem detail.
     */
    @ExceptionHandler(InvalidPasskeyLabelException.class)
    public ResponseEntity<ProblemDetail> handleInvalidLabel(final InvalidPasskeyLabelException exception) {
        return respond(HttpStatus.BAD_REQUEST, "invalid-label", "Invalid label", exception.getMessage());
    }

    /**
     * Answers a path parameter that breaks the constraints of the contract (an identifier that is not unpadded
     * base64url): the validation of the generated interface throws it, and without this answer it would be a
     * {@code 500}.
     *
     * @param exception the failure.
     * @return the {@code 400} problem detail.
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ProblemDetail> handleInvalidParameter(final ConstraintViolationException exception) {
        return respond(HttpStatus.BAD_REQUEST, "invalid-parameter", "Invalid parameter", exception.getMessage());
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
