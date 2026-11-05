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

import com.irurueta.authserver.authorization.domain.account.InvalidAccountTokenException;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordException;
import com.irurueta.authserver.authorization.domain.password.InvalidCredentialsException;
import com.irurueta.authserver.authorization.domain.password.InvalidPasswordException;
import com.irurueta.authserver.authorization.domain.password.PasswordViolation;
import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Translates the failures of {@link AccountController} to RFC 9457 problem details. Request validation failures are
 * handled by the parent class, which already answers problem details. The messages never say whether an e-mail
 * address exists.
 */
@RestControllerAdvice(assignableTypes = AccountController.class)
public class AccountExceptionHandler extends ResponseEntityExceptionHandler {

    /** Base of the problem type URNs. */
    private static final String TYPE_BASE = "urn:problem:account:";

    /** Name of the property that lists the broken password rules. */
    static final String VIOLATIONS_PROPERTY = "violations";

    /**
     * Answers a password that breaks the password policy.
     *
     * @param exception the failure.
     * @return the problem detail, listing the broken rules.
     */
    @ExceptionHandler(InvalidPasswordException.class)
    public ResponseEntity<ProblemDetail> handleInvalidPassword(final InvalidPasswordException exception) {
        final var problem = problem("invalid-password", "Invalid password",
                "The password does not satisfy the password policy");
        problem.setProperty(VIOLATIONS_PROPERTY,
                exception.getViolations().stream().map(PasswordViolation::name).toList());
        return respond(problem);
    }

    /**
     * Answers a password known to be compromised.
     *
     * @param exception the failure.
     * @return the problem detail.
     */
    @ExceptionHandler(CompromisedPasswordException.class)
    public ResponseEntity<ProblemDetail> handleCompromisedPassword(final CompromisedPasswordException exception) {
        return respond(problem("compromised-password", "Compromised password", exception.getMessage()));
    }

    /**
     * Answers a wrong current password.
     *
     * @param exception the failure.
     * @return the problem detail.
     */
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ProblemDetail> handleInvalidCredentials(final InvalidCredentialsException exception) {
        return respond(problem("invalid-credentials", "Invalid credentials", exception.getMessage()));
    }

    /**
     * Answers an invalid, expired or already used token.
     *
     * @param exception the failure.
     * @return the problem detail.
     */
    @ExceptionHandler(InvalidAccountTokenException.class)
    public ResponseEntity<ProblemDetail> handleInvalidToken(final InvalidAccountTokenException exception) {
        return respond(problem("invalid-token", "Invalid token", exception.getMessage()));
    }

    /**
     * Builds a bad request problem.
     *
     * @param type   last segment of the problem type.
     * @param title  short summary.
     * @param detail explanation.
     * @return the problem detail.
     */
    private static ProblemDetail problem(final String type, final String title, final String detail) {
        final var problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, detail);
        problem.setType(URI.create(TYPE_BASE + type));
        problem.setTitle(title);
        return problem;
    }

    /**
     * Wraps a problem into its response.
     *
     * @param problem the problem.
     * @return the response carrying the problem's status.
     */
    private static ResponseEntity<ProblemDetail> respond(final ProblemDetail problem) {
        return ResponseEntity.status(problem.getStatus()).body(problem);
    }
}
