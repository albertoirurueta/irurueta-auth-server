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
package com.irurueta.authserver.bff.api.web.login;

import jakarta.validation.ConstraintViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Answers a login request whose parameters break the constraints of the contract ({@code returnTo} too long,
 * {@code acrValues} of the wrong format, {@code maxAge} out of range) with {@code 400}, as the contract declares: the
 * validation of the generated interface throws a {@link ConstraintViolationException}, which would otherwise be a
 * {@code 500}. Like the other {@code 400} of the login, the answer has no body.
 */
@RestControllerAdvice(assignableTypes = BffLoginController.class)
public class BffLoginExceptionHandler {

    /**
     * Answers a parameter that breaks the constraints of the contract.
     *
     * @param exception the failure.
     * @return an empty {@code 400} answer.
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Void> handleInvalidParameter(final ConstraintViolationException exception) {
        return ResponseEntity.badRequest().build();
    }
}
