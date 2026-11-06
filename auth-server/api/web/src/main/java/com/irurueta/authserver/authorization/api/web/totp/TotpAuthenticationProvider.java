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

import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.application.totp.VerifyRecoveryCodeUseCase;
import com.irurueta.authserver.authorization.application.totp.VerifyTotpUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockedException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Verifies a TOTP code or a recovery code for the signed-in user. The use cases count the failures, lock the second
 * factor after too many and clear the counter on success; a locked second factor is rejected even for a correct
 * code. A correct code answers with the authentication the user already holds plus the TOTP factor authority.
 */
@RequiredArgsConstructor
public class TotpAuthenticationProvider implements AuthenticationProvider {

    /** Use case that verifies a TOTP code. */
    private final VerifyTotpUseCase verifyTotpUseCase;

    /** Use case that verifies (and consumes) a recovery code. */
    private final VerifyRecoveryCodeUseCase verifyRecoveryCodeUseCase;

    /** Resolves the identifier of the account of the signed-in user. */
    private final SecondFactorUserResolver userResolver;

    /** Adds the factor authority to an authentication. */
    private final FactorGrantor factorGrantor;

    // tag::totp-filter[]
    /**
     * Verifies the code.
     *
     * @param authentication the {@link TotpAuthenticationToken} to verify.
     * @return the authentication the user already holds with the TOTP factor added.
     * @throws AuthenticationException if the code is wrong, the second factor is locked or the account is unknown.
     */
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final var request = (TotpAuthenticationToken) authentication;
        final var primary = request.primary();
        final var username = primary.getName();
        final var userId = userResolver.userIdOf(username);
        final boolean accepted;
        try {
            accepted = request.isRecovery()
                    ? verifyRecoveryCodeUseCase.execute(userId, username, request.getCredentials())
                    : verifyTotpUseCase.execute(userId, username, request.getCredentials());
        } catch (final SecondFactorLockedException e) {
            throw new LockedException("The second factor is locked", e);
        }
        if (!accepted) {
            throw new BadCredentialsException("The code is not valid");
        }
        return factorGrantor.grant(primary, TotpFactor.AUTHORITY);
    }
    // end::totp-filter[]

    /**
     * Tells which requests this provider verifies.
     *
     * @param authentication the type of the request.
     * @return {@code true} for a {@link TotpAuthenticationToken}.
     */
    @Override
    public boolean supports(final Class<?> authentication) {
        return TotpAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
