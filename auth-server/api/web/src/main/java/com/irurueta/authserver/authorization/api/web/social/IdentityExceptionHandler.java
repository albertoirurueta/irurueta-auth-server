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

import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.IdentitiesApi;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Answers the failures of the identities API as {@code application/problem+json}. The last-sign-in-method and step-up
 * answers are the shared ones of {@link SignInMethodExceptionHandler}.
 */
@RestControllerAdvice(assignableTypes = IdentitiesApi.class)
public class IdentityExceptionHandler extends SignInMethodExceptionHandler {

    /** Base of the problem type URNs. */
    private static final String TYPE_BASE = "urn:problem:identity:";

    /**
     * Creates the handler.
     *
     * @param mfaExceptionHandler builds the step-up challenge.
     */
    public IdentityExceptionHandler(final MfaExceptionHandler mfaExceptionHandler) {
        super(TYPE_BASE, mfaExceptionHandler);
    }

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
}
