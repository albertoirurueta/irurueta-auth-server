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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.ott.OneTimeTokenAuthentication;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Confirms a magic link: consumes the token Spring's {@code JdbcOneTimeTokenService} stored and signs the user in with
 * it. It does what Spring's own provider does, except that it also reads the purpose the link was requested for
 * ({@link LinkTokenUsername}), which Spring's provider cannot because it would look the marked user name up as it is:
 * <ul>
 * <li>a link requested for a sign-in answers with the user's authentication plus {@code FACTOR_OTT};</li>
 * <li>a link requested as a second factor is refused unless the session that confirms it is the signed-in session of
 * the same user, with a primary factor that is not the e-mail channel itself; it then answers with the second-factor
 * authority of the e-mail channel, and Spring Security's authentication filter merges it with the factors the session
 * holds.</li>
 * </ul>
 * Links are delivered by e-mail only. The account is loaded through the user service of the chain, which refuses a
 * disabled, locked or expired account.
 */
@RequiredArgsConstructor
public class OttLinkAuthenticationProvider implements AuthenticationProvider {

    /** Store of the link tokens. */
    private final OneTimeTokenService oneTimeTokenService;

    /** Loads the account, refusing one that cannot sign in. */
    private final UserDetailsService userDetailsService;

    /** Adds the factor authority to an authentication. */
    private final FactorGrantor factorGrantor;

    /** Rules about the session a second factor is presented in. */
    private final PrimaryFactorSession primaryFactorSession;

    /**
     * Consumes the token and builds the authentication.
     *
     * @param authentication the {@link OneTimeTokenAuthenticationToken} to confirm.
     * @return the authentication of the user, with the factor of the purpose of the link.
     * @throws AuthenticationException if the token is not valid, the account cannot sign in or a second-factor link
     *                                 is confirmed outside the session of the user it was requested for.
     */
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final var consumed = oneTimeTokenService.consume((OneTimeTokenAuthenticationToken) authentication);
        if (consumed == null) {
            throw new InvalidOneTimeTokenException("Invalid token");
        }
        final var secondFactor = LinkTokenUsername.isSecondFactor(consumed.getUsername());
        final var username = LinkTokenUsername.identifierOf(consumed.getUsername());
        if (secondFactor) {
            requirePrimaryFactorSessionOf(username);
        }
        try {
            final var user = userDetailsService.loadUserByUsername(username);
            final var signedIn = new OneTimeTokenAuthentication(user, user.getAuthorities());
            signedIn.setDetails(authentication.getDetails());
            return factorGrantor.grant(signedIn, secondFactor ? OttFactors.EMAIL_SECOND_FACTOR_AUTHORITY
                    : OttFactors.EMAIL_AUTHORITY);
        } catch (final UsernameNotFoundException e) {
            throw new BadCredentialsException("Failed to authenticate the one-time token", e);
        }
    }

    /**
     * Tells which requests this provider confirms.
     *
     * @param authentication the type of the request.
     * @return {@code true} for a {@link OneTimeTokenAuthenticationToken}.
     */
    @Override
    public boolean supports(final Class<?> authentication) {
        return OneTimeTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Requires the current session to be the signed-in session of a user who still has to present a second factor.
     *
     * @param username the user the link was requested for.
     * @throws BadCredentialsException if the session is another user's, holds no primary factor, or signed in through
     *                                 the e-mail channel the link was delivered by.
     */
    private void requirePrimaryFactorSessionOf(final String username) {
        final var current = SecurityContextHolder.getContext().getAuthentication();
        if (!primaryFactorSession.holdsPrimaryFactor(current) || !username.equals(current.getName())
                || primaryFactorSession.signedInThrough(current, OttChannel.EMAIL)) {
            throw new BadCredentialsException("A second-factor link only works in the session it was requested in");
        }
    }
}
