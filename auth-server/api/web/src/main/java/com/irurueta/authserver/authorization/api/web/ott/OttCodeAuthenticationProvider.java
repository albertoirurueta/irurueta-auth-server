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
import com.irurueta.authserver.authorization.application.ott.OttVerificationResult;
import com.irurueta.authserver.authorization.application.ott.VerifyOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import java.util.EnumSet;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.ott.OneTimeTokenAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Signs a user in with a numeric one-time code, delivered by e-mail or SMS, through {@link VerifyOneTimeCodeUseCase}.
 * The code only counts in the session whose binding id it was stored with, and is consumed by the first correct
 * submission. The account is loaded through the user service of the chain, which refuses a disabled, locked or expired
 * account. A correct code answers with the user's authentication plus the sign-in authority of the channel the code
 * was delivered through ({@code FACTOR_OTT} for e-mail, {@code FACTOR_OTT_SMS} for SMS), which Spring Security's
 * authentication filter merges with the factors the session already holds.
 */
@RequiredArgsConstructor
public class OttCodeAuthenticationProvider implements AuthenticationProvider {

    /** Verifies the code. */
    private final VerifyOneTimeCodeUseCase verifyOneTimeCodeUseCase;

    /** Loads the account, refusing one that cannot sign in. */
    private final UserDetailsService userDetailsService;

    /** Adds the factor authority to an authentication. */
    private final FactorGrantor factorGrantor;

    /**
     * Verifies the code.
     *
     * @param authentication the {@link OttCodeAuthenticationToken} to verify.
     * @return the authentication of the user, with the factor of the channel.
     * @throws AuthenticationException if the code is not valid or the account cannot sign in.
     */
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final var request = (OttCodeAuthenticationToken) authentication;
        final var result = verifyOneTimeCodeUseCase.execute(request.bindingId(), request.getPrincipal(),
                request.getCredentials(), OttPurpose.LOGIN, EnumSet.allOf(OttChannel.class));
        if (result.status() == OttVerificationResult.Status.LOCKED) {
            throw new LockedException("The second factor is locked");
        }
        if (!result.isSuccess()) {
            throw new BadCredentialsException("The code is not valid");
        }
        try {
            final var user = userDetailsService.loadUserByUsername(request.getPrincipal());
            final var signedIn = new OneTimeTokenAuthentication(user, user.getAuthorities());
            return factorGrantor.grant(signedIn, OttFactors.signInAuthority(result.channel()));
        } catch (final UsernameNotFoundException e) {
            throw new BadCredentialsException("The code is not valid", e);
        }
    }

    /**
     * Tells which requests this provider verifies.
     *
     * @param authentication the type of the request.
     * @return {@code true} for an {@link OttCodeAuthenticationToken}.
     */
    @Override
    public boolean supports(final Class<?> authentication) {
        return OttCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
