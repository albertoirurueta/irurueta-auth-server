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

import com.irurueta.authserver.authorization.application.social.ResolveFederatedLoginUseCase;
import com.irurueta.authserver.authorization.domain.social.FederatedLoginRefusedException;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

// tag::social-account-resolver[]
/**
 * Finds the local account of a sign-in with an external provider and refuses it unless that account may sign in.
 *
 * <p>The use case finds, links or provisions the account but does not look at its status, so the account is then
 * loaded through the status-checking user service (the rules of
 * {@code AccountStatusUserDetailsService}: a disabled, locked or expired account is refused, exactly as the password
 * and passkey sign-ins refuse it). Every refusal is the same {@code access_denied} error, which the login chain turns
 * into the generic failure of the login page, so the answer never says whether an account exists or why it was
 * refused.
 */
@RequiredArgsConstructor
public class FederatedAccountResolver {

    /** Error description of every refusal. */
    static final String REFUSED = "The sign-in with the external provider was refused";

    /** Use case that finds, links or provisions the account. */
    private final ResolveFederatedLoginUseCase resolveFederatedLoginUseCase;

    /** Loads the account, refusing one that may not sign in. */
    private final UserDetailsService accountStatusUserDetailsService;

    /**
     * Resolves a sign-in.
     *
     * @param provider      the provider that authenticated the user.
     * @param subject       the provider's stable identifier of the user.
     * @param email         e-mail address the provider reported, or {@code null}.
     * @param emailVerified whether the provider vouches for the address.
     * @return the local account, which may sign in.
     * @throws OAuth2AuthenticationException if the sign-in is refused: the provider did not verify the address, the
     *                                       address belongs to an unverified account, or the account is disabled,
     *                                       locked or expired.
     */
    public UserDetails resolve(
            final IdentityProvider provider, final String subject, final String email, final boolean emailVerified) {
        try {
            final var login = resolveFederatedLoginUseCase.execute(provider, subject, email, emailVerified);
            return accountStatusUserDetailsService.loadUserByUsername(login.account().username());
        } catch (final FederatedLoginRefusedException | AuthenticationException e) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, REFUSED, null), e);
        }
    }
}
// end::social-account-resolver[]
