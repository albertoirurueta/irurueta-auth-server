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

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.mfa.StepUpGuard;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.CertificatesApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.BindCertificateRequest;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.Certificate;
import com.irurueta.authserver.authorization.application.x509.BindCertificateUseCase;
import com.irurueta.authserver.authorization.application.x509.ListCertificatesUseCase;
import com.irurueta.authserver.authorization.application.x509.UnbindCertificateUseCase;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

// tag::x509-certificate-controller[]
/**
 * Manages the client certificates bound to the authenticated account (the operations of the contract). Binding and
 * unbinding change how the account signs in, so both call {@link StepUpGuard} first, as unlinking an identity does.
 * The controller exists whether or not the sign-in with a certificate is enabled, so certificates can be bound before
 * it is turned on.
 */
@RestController
@RequiredArgsConstructor
public class CertificateController implements CertificatesApi {

    /** Resolves the account of the request. */
    private final CurrentAccountResolver currentAccountResolver;

    /** Lists the certificates of an account. */
    private final ListCertificatesUseCase listCertificatesUseCase;

    /** Binds a certificate. */
    private final BindCertificateUseCase bindCertificateUseCase;

    /** Unbinds a certificate. */
    private final UnbindCertificateUseCase unbindCertificateUseCase;

    /** Requires a recent multi-factor sign-in before a certificate is bound or unbound. */
    private final StepUpGuard stepUpGuard;

    /** Reads the certificate of a bind request. */
    private final PemCertificateReader pemCertificateReader;

    /** Maps the bindings onto the contract's DTOs. */
    private final CertificateDtoMapper certificateDtoMapper;

    /**
     * Lists the certificates bound to the authenticated account.
     *
     * @return {@code 200 OK} with the certificates, possibly none.
     */
    @Override
    public ResponseEntity<List<Certificate>> listCertificates() {
        final var account = currentAccountResolver.resolve();
        return ResponseEntity.ok(certificateDtoMapper.toResponses(listCertificatesUseCase.execute(account.id())));
    }

    /**
     * Binds a certificate to the authenticated account.
     *
     * @param request the PEM certificate.
     * @return {@code 201 Created} with the binding.
     * @throws InvalidCertificateException if the value is not a usable certificate.
     * @throws com.irurueta.authserver.authorization.domain.x509.CertificateAlreadyBoundException
     *         if the certificate is bound to another account.
     * @throws com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException
     *         if the account has a confirmed second factor and the token does not show a recent multi-factor
     *         sign-in.
     */
    @Override
    public ResponseEntity<Certificate> bindCertificate(final BindCertificateRequest request) {
        final var account = currentAccountResolver.resolve();
        stepUpGuard.requireRecentMultiFactor(account.id());
        final var certificate = pemCertificateReader.read(request.certificate());
        final var binding = bindCertificateUseCase.execute(account.id(), account.username(),
                certificate.fingerprintSha256(), certificate.subjectDn());
        return ResponseEntity.status(HttpStatus.CREATED).body(certificateDtoMapper.toResponse(binding));
    }

    /**
     * Unbinds a certificate of the authenticated account.
     *
     * @param id identifier of the binding.
     * @return {@code 204 No Content}.
     * @throws com.irurueta.authserver.authorization.domain.x509.CertificateNotFoundException
     *         if the account has no such certificate.
     * @throws com.irurueta.authserver.authorization.domain.social.LastSignInMethodException
     *         if the certificate is the last way the account can sign in.
     * @throws com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException
     *         if the account has a confirmed second factor and the token does not show a recent multi-factor
     *         sign-in.
     */
    @Override
    public ResponseEntity<Void> unbindCertificate(final UUID id) {
        final var account = currentAccountResolver.resolve();
        stepUpGuard.requireRecentMultiFactor(account.id());
        unbindCertificateUseCase.execute(account.id(), account.username(), id);
        return ResponseEntity.noContent().build();
    }
}
// end::x509-certificate-controller[]
