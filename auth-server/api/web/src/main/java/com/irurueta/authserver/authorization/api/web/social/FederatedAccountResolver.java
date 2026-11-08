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

import com.irurueta.authserver.authorization.application.social.LinkIdentityUseCase;
import com.irurueta.authserver.authorization.application.social.ResolveFederatedLoginUseCase;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityAlreadyLinkedException;
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
 * <p>The use case finds, links or provisions the account and refuses a disabled one before it links anything; the
 * account is then loaded through the status-checking user service as well (the rules of
 * {@code AccountStatusUserDetailsService}: a disabled, locked or expired account is refused, exactly as the password
 * and passkey sign-ins refuse it). Every refusal is the same {@code access_denied} error, which the login chain turns
 * into the generic failure of the login page, so the answer never says whether an account exists or why it was
 * refused.
 *
 * <p>When the signed-in user asked to link this provider ({@link PendingIdentityLinks}), the identity is linked to
 * that account through {@link LinkIdentityUseCase} instead: nothing is resolved by e-mail address or provisioned, and
 * an identity that belongs to another account is refused with {@link #LINK_REFUSED}, which the failure handler sends
 * back to the identities page.
 */
@RequiredArgsConstructor
public class FederatedAccountResolver {

    /** Error description of every refusal. */
    static final String REFUSED = "The sign-in with the external provider was refused";

    /** Error code of a refused link: the identity belongs to another account. */
    public static final String LINK_REFUSED = "identity_link_refused";

    /** Error description of a refused link. */
    static final String LINK_REFUSED_DESCRIPTION = "The identity is linked to another account";

    /** Use case that finds, links or provisions the account. */
    private final ResolveFederatedLoginUseCase resolveFederatedLoginUseCase;

    /** Loads the account, refusing one that may not sign in. */
    private final UserDetailsService accountStatusUserDetailsService;

    /** Use case that links an identity to the signed-in account. */
    private final LinkIdentityUseCase linkIdentityUseCase;

    /** The link markers of the explicit link flow. */
    private final PendingIdentityLinks pendingIdentityLinks;

    /**
     * Resolves a sign-in.
     *
     * @param provider      the provider that authenticated the user.
     * @param subject       the provider's stable identifier of the user.
     * @param email         e-mail address the provider reported, or {@code null}.
     * @param emailVerified whether the provider vouches for the address.
     * @return the local account, which may sign in; for a link, the signed-in account.
     * @throws OAuth2AuthenticationException if the sign-in is refused: the provider did not verify the address, the
     *                                       address belongs to an unverified account, or the account is disabled,
     *                                       locked or expired; or if a link is refused because the identity belongs to
     *                                       another account.
     */
    public UserDetails resolve(
            final IdentityProvider provider, final String subject, final String email, final boolean emailVerified) {
        final var link = pendingIdentityLinks.consume(provider);
        if (link.isPresent()) {
            return link(link.get(), provider, subject, email);
        }
        try {
            final var login = resolveFederatedLoginUseCase.execute(provider, subject, email, emailVerified);
            return accountStatusUserDetailsService.loadUserByUsername(login.account().username());
        } catch (final FederatedLoginRefusedException | AuthenticationException e) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, REFUSED, null), e);
        }
    }

    /**
     * Links an identity to the signed-in account that asked for it.
     *
     * @param link     the link marker.
     * @param provider the provider that authenticated the user.
     * @param subject  the provider's stable identifier of the user.
     * @param email    e-mail address the provider reported, or {@code null}.
     * @return the signed-in account.
     * @throws OAuth2AuthenticationException if the identity belongs to another account, or the account may no longer
     *                                       sign in.
     */
    private UserDetails link(final PendingIdentityLink link, final IdentityProvider provider, final String subject,
                             final String email) {
        try {
            linkIdentityUseCase.execute(link.userId(), link.username(), provider, subject, email);
            return accountStatusUserDetailsService.loadUserByUsername(link.username());
        } catch (final FederatedIdentityAlreadyLinkedException | AuthenticationException e) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(LINK_REFUSED, LINK_REFUSED_DESCRIPTION, null), e);
        }
    }
}
// end::social-account-resolver[]
