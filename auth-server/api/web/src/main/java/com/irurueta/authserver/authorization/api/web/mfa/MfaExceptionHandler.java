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

import com.irurueta.authserver.authorization.api.web.ProblemJsonExceptionHandler;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.RecoveryCodesApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.TotpApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.TrustedDevicesApi;
import com.irurueta.authserver.authorization.domain.totp.InvalidTotpCodeException;
import com.irurueta.authserver.authorization.domain.totp.TotpAlreadyEnabledException;
import com.irurueta.authserver.authorization.domain.totp.TotpNotEnrolledException;
import java.net.URI;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Translates the failures of the authenticator app, recovery code and trusted device endpoints to RFC 9457 problem
 * details, answered as {@code application/problem+json}. It is scoped to the generated interfaces of those
 * endpoints, so it covers their controllers without depending on the packages they live in. Request validation
 * failures are handled by the parent class. A missing step-up ({@link StepUpGuard}) is answered as RFC 9470 describes.
 */
@RestControllerAdvice(assignableTypes = {TotpApi.class, RecoveryCodesApi.class, TrustedDevicesApi.class})
public class MfaExceptionHandler extends ProblemJsonExceptionHandler {

    /** Base of the problem type URNs. */
    private static final String TYPE_BASE = "urn:problem:mfa:";

    /**
     * Answers an enrolment of an authenticator app that is already enabled.
     *
     * @param exception the failure.
     * @return the {@code 409} problem detail.
     */
    @ExceptionHandler(TotpAlreadyEnabledException.class)
    public ResponseEntity<ProblemDetail> handleAlreadyEnabled(final TotpAlreadyEnabledException exception) {
        return respond(HttpStatus.CONFLICT, "totp-already-enabled", "Authenticator app already enabled",
                exception.getMessage());
    }

    /**
     * Answers a confirmation without an enrolment in progress.
     *
     * @param exception the failure.
     * @return the {@code 400} problem detail.
     */
    @ExceptionHandler(TotpNotEnrolledException.class)
    public ResponseEntity<ProblemDetail> handleNotEnrolled(final TotpNotEnrolledException exception) {
        return respond(HttpStatus.BAD_REQUEST, "totp-not-enrolled", "No enrolment in progress",
                exception.getMessage());
    }

    /**
     * Answers a wrong code.
     *
     * @param exception the failure.
     * @return the {@code 400} problem detail.
     */
    @ExceptionHandler(InvalidTotpCodeException.class)
    public ResponseEntity<ProblemDetail> handleInvalidCode(final InvalidTotpCodeException exception) {
        return respond(HttpStatus.BAD_REQUEST, "invalid-code", "Invalid code", exception.getMessage());
    }

    /**
     * Answers a device the account does not have.
     *
     * @param exception the failure.
     * @return the {@code 404} problem detail.
     */
    @ExceptionHandler(TrustedDeviceNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleDeviceNotFound(final TrustedDeviceNotFoundException exception) {
        return respond(HttpStatus.NOT_FOUND, "trusted-device-not-found", "Trusted device not found",
                exception.getMessage());
    }

    // tag::mfa-step-up-challenge[]
    /**
     * Answers a token whose sign-in is not recent or strong enough: {@code 401} with the RFC 9470 challenge, which
     * tells the client which {@code acr_values} and {@code max_age} to ask for when it signs the user in again.
     *
     * @param exception the failure.
     * @return the {@code 401} problem detail with the {@code WWW-Authenticate} challenge.
     */
    @ExceptionHandler(InsufficientUserAuthenticationException.class)
    public ResponseEntity<ProblemDetail> handleInsufficientUserAuthentication(
            final InsufficientUserAuthenticationException exception) {
        final var problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, exception.getMessage());
        problem.setType(URI.create(TYPE_BASE + "insufficient-user-authentication"));
        problem.setTitle("Step-up authentication required");
        final var headers = new HttpHeaders();
        headers.set(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"insufficient_user_authentication\", acr_values=\""
                + exception.getAcrValues() + "\", max_age=\"" + exception.getMaxAge().toSeconds() + "\"");
        return problemResponse(problem, headers);
    }
    // end::mfa-step-up-challenge[]

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
