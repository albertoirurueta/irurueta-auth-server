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

package com.irurueta.authserver.authorization.api.web.passkeys;

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.mfa.StepUpGuard;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.PasskeysApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.Passkey;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.RenamePasskeyRequest;
import com.irurueta.authserver.authorization.application.passkeys.DeletePasskeyUseCase;
import com.irurueta.authserver.authorization.application.passkeys.ListPasskeysUseCase;
import com.irurueta.authserver.authorization.application.passkeys.RenamePasskeyUseCase;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * Manages the passkeys of the authenticated account (the operations of the contract). Registering one is not here:
 * it is the WebAuthn ceremony of the security chain, which the account page drives.
 */
@RestController
@RequiredArgsConstructor
public class PasskeyController implements PasskeysApi {

    /** Resolves the account of the request. */
    private final CurrentAccountResolver currentAccountResolver;

    /** Lists the passkeys of an account. */
    private final ListPasskeysUseCase listPasskeysUseCase;

    /** Renames a passkey. */
    private final RenamePasskeyUseCase renamePasskeyUseCase;

    /** Deletes a passkey. */
    private final DeletePasskeyUseCase deletePasskeyUseCase;

    /** Requires a recent multi-factor sign-in before a passkey is deleted. */
    private final StepUpGuard stepUpGuard;

    /** Maps the passkeys onto the contract's DTOs. */
    private final PasskeyDtoMapper passkeyDtoMapper;

    /**
     * Lists the passkeys of the authenticated account.
     *
     * @return {@code 200 OK} with the passkeys, possibly none.
     */
    @Override
    public ResponseEntity<List<Passkey>> listPasskeys() {
        final var account = currentAccountResolver.resolve();
        return ResponseEntity.ok(passkeyDtoMapper.toResponses(listPasskeysUseCase.execute(account.username())));
    }

    /**
     * Renames a passkey of the authenticated account.
     *
     * @param id      credential identifier of the passkey.
     * @param request the new label.
     * @return {@code 200 OK} with the renamed passkey.
     * @throws com.irurueta.authserver.authorization.domain.passkeys.PasskeyNotFoundException
     *         if the account has no such passkey.
     */
    @Override
    public ResponseEntity<Passkey> renamePasskey(final String id, final RenamePasskeyRequest request) {
        final var account = currentAccountResolver.resolve();
        return ResponseEntity.ok(passkeyDtoMapper.toResponse(
                renamePasskeyUseCase.execute(account.username(), id, request.label())));
    }

    /**
     * Deletes a passkey of the authenticated account.
     *
     * @param id credential identifier of the passkey.
     * @return {@code 204 No Content}.
     * @throws com.irurueta.authserver.authorization.domain.passkeys.PasskeyNotFoundException
     *         if the account has no such passkey.
     * @throws com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException
     *         if the account has a confirmed second factor and the token does not show a recent multi-factor
     *         sign-in.
     */
    @Override
    public ResponseEntity<Void> deletePasskey(final String id) {
        final var account = currentAccountResolver.resolve();
        stepUpGuard.requireRecentMultiFactor(account.id());
        deletePasskeyUseCase.execute(account.id(), account.username(), id);
        return ResponseEntity.noContent().build();
    }
}
