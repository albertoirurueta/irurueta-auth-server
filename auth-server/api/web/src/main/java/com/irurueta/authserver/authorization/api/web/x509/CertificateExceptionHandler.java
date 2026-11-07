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
package com.irurueta.authserver.authorization.api.web.x509;

import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.api.web.social.SignInMethodExceptionHandler;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.CertificatesApi;
import com.irurueta.authserver.authorization.domain.x509.CertificateAlreadyBoundException;
import com.irurueta.authserver.authorization.domain.x509.CertificateNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Answers the failures of the certificates API as {@code application/problem+json}. The last-sign-in-method and step-up
 * answers are the shared ones of {@link SignInMethodExceptionHandler}, so a client handles them as for the identities.
 */
@RestControllerAdvice(assignableTypes = CertificatesApi.class)
public class CertificateExceptionHandler extends SignInMethodExceptionHandler {

    /** Base of the problem type URNs. */
    private static final String TYPE_BASE = "urn:problem:certificate:";

    /**
     * Creates the handler.
     *
     * @param mfaExceptionHandler builds the step-up challenge.
     */
    public CertificateExceptionHandler(final MfaExceptionHandler mfaExceptionHandler) {
        super(TYPE_BASE, mfaExceptionHandler);
    }

    /**
     * Answers a value that is not a usable certificate.
     *
     * @param exception the failure.
     * @return the {@code 400} problem detail.
     */
    @ExceptionHandler(InvalidCertificateException.class)
    public ResponseEntity<ProblemDetail> handleInvalidCertificate(final InvalidCertificateException exception) {
        return respond(HttpStatus.BAD_REQUEST, "invalid-certificate", "Invalid certificate", exception.getMessage());
    }

    /**
     * Answers a certificate that is bound to another account.
     *
     * @param exception the failure.
     * @return the {@code 409} problem detail.
     */
    @ExceptionHandler(CertificateAlreadyBoundException.class)
    public ResponseEntity<ProblemDetail> handleAlreadyBound(final CertificateAlreadyBoundException exception) {
        return respond(HttpStatus.CONFLICT, "certificate-already-bound", "Certificate already bound",
                exception.getMessage());
    }

    /**
     * Answers a certificate the account does not have (another account's certificate is answered the same way).
     *
     * @param exception the failure.
     * @return the {@code 404} problem detail.
     */
    @ExceptionHandler(CertificateNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(final CertificateNotFoundException exception) {
        return respond(HttpStatus.NOT_FOUND, "certificate-not-found", "Certificate not found", exception.getMessage());
    }
}
