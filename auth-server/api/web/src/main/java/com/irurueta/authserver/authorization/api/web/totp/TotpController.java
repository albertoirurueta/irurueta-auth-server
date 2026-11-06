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

package com.irurueta.authserver.authorization.api.web.totp;

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.TotpApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.ConfirmTotpRequest;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.RecoveryCodesResponse;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.TotpEnrollmentResponse;
import com.irurueta.authserver.authorization.application.totp.ConfirmTotpUseCase;
import com.irurueta.authserver.authorization.application.totp.DisableTotpUseCase;
import com.irurueta.authserver.authorization.application.totp.EnrollTotpUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

// tag::totp-enrollment[]
/**
 * Enrols, confirms and disables the authenticator app of the authenticated account. The paths, status codes and
 * bodies are those of the contract {@code apis/auth-server/rest-server/auth-server-api-v1.yaml}, through the
 * generated {@link TotpApi}; failures are answered by
 * {@link com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler}. Answers that carry a secret are
 * never cached.
 */
@RestController
@RequiredArgsConstructor
public class TotpController implements TotpApi {

    /** Resolves the account of the request. */
    private final CurrentAccountResolver currentAccountResolver;

    /** Starts an enrolment. */
    private final EnrollTotpUseCase enrollTotpUseCase;

    /** Confirms an enrolment. */
    private final ConfirmTotpUseCase confirmTotpUseCase;

    /** Disables the authenticator app. */
    private final DisableTotpUseCase disableTotpUseCase;

    /** Renders the enrolment URI as a QR code. */
    private final QrCodeRenderer qrCodeRenderer;

    /** Maps the results onto the contract's DTOs. */
    private final TotpDtoMapper totpDtoMapper;

    /**
     * Starts the enrolment of an authenticator app.
     *
     * @return {@code 200 OK} with the {@code otpauth} URI and its QR code.
     */
    @Override
    public ResponseEntity<TotpEnrollmentResponse> enrollTotp() {
        final var account = currentAccountResolver.resolve();
        final var uri = enrollTotpUseCase.execute(account.id(), account.username());
        return noStore(totpDtoMapper.toEnrollmentResponse(uri, qrCodeRenderer.render(uri)));
    }

    /**
     * Confirms the enrolment with a code from the authenticator app.
     *
     * @param request the code.
     * @return {@code 200 OK} with the recovery codes, shown only once.
     */
    @Override
    public ResponseEntity<RecoveryCodesResponse> confirmTotp(final ConfirmTotpRequest request) {
        final var account = currentAccountResolver.resolve();
        return noStore(totpDtoMapper.toRecoveryCodesResponse(
                confirmTotpUseCase.execute(account.id(), request.code())));
    }

    /**
     * Disables the authenticator app and removes the recovery codes.
     *
     * @return {@code 204 No Content}.
     */
    @Override
    public ResponseEntity<Void> disableTotp() {
        disableTotpUseCase.execute(currentAccountResolver.resolve().id());
        return ResponseEntity.noContent().build();
    }

    /**
     * Answers a body that carries a secret, which must not be cached.
     *
     * @param body the body.
     * @param <T>  type of the body.
     * @return {@code 200 OK} with {@code Cache-Control: no-store}.
     */
    private static <T> ResponseEntity<T> noStore(final T body) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body);
    }
}
// end::totp-enrollment[]
