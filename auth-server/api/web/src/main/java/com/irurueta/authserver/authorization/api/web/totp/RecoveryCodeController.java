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
import com.irurueta.authserver.authorization.api.web.mfa.StepUpGuard;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.RecoveryCodesApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.RecoveryCodesResponse;
import com.irurueta.authserver.authorization.application.totp.GenerateRecoveryCodesUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * Generates a new set of recovery codes for the authenticated account. The path, status codes and body are those of
 * the contract {@code apis/auth-server/rest-server/auth-server-api-v1.yaml}, through the generated
 * {@link RecoveryCodesApi}. The answer is never cached, since it carries the codes. Replacing the codes needs a recent
 * multi-factor sign-in ({@link StepUpGuard}).
 */
@RestController
@RequiredArgsConstructor
public class RecoveryCodeController implements RecoveryCodesApi {

    /** Resolves the account of the request. */
    private final CurrentAccountResolver currentAccountResolver;

    /** Requires a recent multi-factor sign-in before the codes are replaced. */
    private final StepUpGuard stepUpGuard;

    /** Generates the codes. */
    private final GenerateRecoveryCodesUseCase generateRecoveryCodesUseCase;

    /** Maps the codes onto the contract's DTO. */
    private final TotpDtoMapper totpDtoMapper;

    /**
     * Replaces the recovery codes of the authenticated account.
     *
     * @return {@code 200 OK} with the new codes, shown only once.
     * @throws com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException if the token
     *         does not show a recent multi-factor sign-in.
     */
    @Override
    public ResponseEntity<RecoveryCodesResponse> generateRecoveryCodes() {
        final var userId = currentAccountResolver.resolve().id();
        stepUpGuard.requireRecentMultiFactor(userId);
        final var codes = generateRecoveryCodesUseCase.execute(userId);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(totpDtoMapper.toRecoveryCodesResponse(codes));
    }
}
