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

import com.irurueta.authserver.authorization.api.web.v1.generated.api.TrustedDevicesApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.TrustedDeviceResponse;
import com.irurueta.authserver.authorization.application.mfa.ListTrustedDevicesUseCase;
import com.irurueta.authserver.authorization.application.mfa.RevokeTrustedDeviceUseCase;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * Lists and revokes the trusted devices of the authenticated account. The paths, status codes and bodies are those
 * of the contract {@code apis/auth-server/rest-server/auth-server-api-v1.yaml}, through the generated
 * {@link TrustedDevicesApi}; failures are answered by {@link MfaExceptionHandler}. Revoking a device needs a recent
 * multi-factor sign-in ({@link StepUpGuard}).
 */
@RestController
@RequiredArgsConstructor
public class TrustedDeviceController implements TrustedDevicesApi {

    /** Resolves the account of the request. */
    private final CurrentAccountResolver currentAccountResolver;

    /** Lists the devices of an account. */
    private final ListTrustedDevicesUseCase listTrustedDevicesUseCase;

    /** Revokes a device. */
    private final RevokeTrustedDeviceUseCase revokeTrustedDeviceUseCase;

    /** Requires a recent multi-factor sign-in before a device is revoked. */
    private final StepUpGuard stepUpGuard;

    /** Maps the devices onto the contract's DTOs. */
    private final TrustedDeviceDtoMapper trustedDeviceDtoMapper;

    /**
     * Lists the devices that are still trusted.
     *
     * @return {@code 200 OK} with the devices of the authenticated account.
     */
    @Override
    public ResponseEntity<List<TrustedDeviceResponse>> listTrustedDevices() {
        final var account = currentAccountResolver.resolve();
        return ResponseEntity.ok(trustedDeviceDtoMapper.toResponses(listTrustedDevicesUseCase.execute(account.id())));
    }

    /**
     * Revokes a device of the authenticated account.
     *
     * @param id identifier of the device.
     * @return {@code 204 No Content}.
     * @throws TrustedDeviceNotFoundException          if the account has no such device.
     * @throws InsufficientUserAuthenticationException if the token does not show a recent multi-factor sign-in.
     */
    @Override
    public ResponseEntity<Void> revokeTrustedDevice(final UUID id) {
        final var account = currentAccountResolver.resolve();
        stepUpGuard.requireRecentMultiFactor(account.id());
        if (!revokeTrustedDeviceUseCase.execute(account.id(), account.username(), id)) {
            throw new TrustedDeviceNotFoundException(id);
        }
        return ResponseEntity.noContent().build();
    }
}
