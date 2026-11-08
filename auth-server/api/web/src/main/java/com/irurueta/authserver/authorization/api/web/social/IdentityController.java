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

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.mfa.StepUpGuard;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.IdentitiesApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.Identity;
import com.irurueta.authserver.authorization.application.social.ListIdentitiesUseCase;
import com.irurueta.authserver.authorization.application.social.UnlinkIdentityUseCase;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

// tag::social-identity-controller[]
/**
 * Manages the identities of external providers linked to the authenticated account (the operations of the contract).
 * Linking one is not here: it happens when the user signs in with the provider (the verified e-mail address, or the
 * provisioning of a new account), so the API lists and unlinks.
 */
@RestController
@RequiredArgsConstructor
public class IdentityController implements IdentitiesApi {

    /** Resolves the account of the request. */
    private final CurrentAccountResolver currentAccountResolver;

    /** Lists the identities of an account. */
    private final ListIdentitiesUseCase listIdentitiesUseCase;

    /** Unlinks an identity. */
    private final UnlinkIdentityUseCase unlinkIdentityUseCase;

    /** Requires a recent multi-factor sign-in before an identity is unlinked. */
    private final StepUpGuard stepUpGuard;

    /** Maps the identities onto the contract's DTOs. */
    private final IdentityDtoMapper identityDtoMapper;

    /**
     * Lists the identities linked to the authenticated account.
     *
     * @return {@code 200 OK} with the identities, possibly none.
     */
    @Override
    public ResponseEntity<List<Identity>> listIdentities() {
        final var account = currentAccountResolver.resolve();
        return ResponseEntity.ok(identityDtoMapper.toResponses(listIdentitiesUseCase.execute(account.id())));
    }

    /**
     * Unlinks an identity of the authenticated account.
     *
     * @param id identifier of the link.
     * @return {@code 204 No Content}.
     * @throws com.irurueta.authserver.authorization.domain.social.FederatedIdentityNotFoundException
     *         if the account has no such identity.
     * @throws com.irurueta.authserver.authorization.domain.social.LastSignInMethodException
     *         if the identity is the last way the account can sign in.
     * @throws com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException
     *         if the account has a confirmed second factor and the token does not show a recent multi-factor
     *         sign-in.
     */
    @Override
    public ResponseEntity<Void> unlinkIdentity(final UUID id) {
        final var account = currentAccountResolver.resolve();
        stepUpGuard.requireRecentMultiFactor(account.id());
        unlinkIdentityUseCase.execute(account.id(), account.username(), id);
        return ResponseEntity.noContent().build();
    }
}
// end::social-identity-controller[]
