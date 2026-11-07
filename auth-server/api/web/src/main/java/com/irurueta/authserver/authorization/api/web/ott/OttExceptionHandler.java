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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.api.web.ProblemJsonExceptionHandler;
import com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException;
import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.PhoneApi;
import com.irurueta.authserver.authorization.application.sms.InvalidPhoneNumberException;
import com.irurueta.authserver.authorization.application.sms.SmsCountryNotAllowedException;
import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Translates the failures of the phone endpoints to RFC 9457 problem details, answered as
 * {@code application/problem+json}. It is scoped to the generated {@link PhoneApi}, so it covers its controller
 * without depending on the package it lives in. Request validation failures are handled by the parent class. A
 * missing step-up is answered as the multi-factor handler does. The messages never say which numbers are registered.
 */
@RestControllerAdvice(assignableTypes = PhoneApi.class)
@RequiredArgsConstructor
public class OttExceptionHandler extends ProblemJsonExceptionHandler {

    /** Base of the problem type URNs. */
    private static final String TYPE_BASE = "urn:problem:phone:";

    /** Answers a missing step-up. */
    private final MfaExceptionHandler mfaExceptionHandler;

    /**
     * Answers an account without a verified phone.
     *
     * @param exception the failure.
     * @return the {@code 404} problem detail.
     */
    @ExceptionHandler(PhoneNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(final PhoneNotFoundException exception) {
        return respond(HttpStatus.NOT_FOUND, "phone-not-found", "Phone not found", exception.getMessage());
    }

    /**
     * Answers a number that is not a valid phone number.
     *
     * @param exception the failure.
     * @return the {@code 400} problem detail.
     */
    @ExceptionHandler(InvalidPhoneNumberException.class)
    public ResponseEntity<ProblemDetail> handleInvalidPhone(final InvalidPhoneNumberException exception) {
        return respond(HttpStatus.BAD_REQUEST, "invalid-phone", "Invalid phone number", exception.getMessage());
    }

    /**
     * Answers a number of a country SMS messages are not sent to.
     *
     * @param exception the failure.
     * @return the {@code 400} problem detail.
     */
    @ExceptionHandler(SmsCountryNotAllowedException.class)
    public ResponseEntity<ProblemDetail> handleCountryNotAllowed(final SmsCountryNotAllowedException exception) {
        return respond(HttpStatus.BAD_REQUEST, "country-not-allowed", "Country not allowed", exception.getMessage());
    }

    /**
     * Answers a wrong, expired or missing verification code.
     *
     * @param exception the failure.
     * @return the {@code 400} problem detail.
     */
    @ExceptionHandler(InvalidPhoneCodeException.class)
    public ResponseEntity<ProblemDetail> handleInvalidCode(final InvalidPhoneCodeException exception) {
        return respond(HttpStatus.BAD_REQUEST, "invalid-code", "Invalid code", exception.getMessage());
    }

    /**
     * Answers a client or an account that asked or tried too many times, telling when to retry.
     *
     * @param exception the failure.
     * @return the {@code 429} problem detail, with a {@code Retry-After} header in seconds.
     */
    @ExceptionHandler(OttRateLimitExceededException.class)
    public ResponseEntity<ProblemDetail> handleRateLimited(final OttRateLimitExceededException exception) {
        final var problem = ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, exception.getMessage());
        problem.setType(URI.create(TYPE_BASE + "rate-limited"));
        problem.setTitle("Too many requests");
        final var headers = new HttpHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, Long.toString(Math.max(1, exception.getRetryAfter().toSeconds())));
        return problemResponse(problem, headers);
    }

    /**
     * Answers a token whose sign-in is not recent or strong enough to remove the phone.
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
