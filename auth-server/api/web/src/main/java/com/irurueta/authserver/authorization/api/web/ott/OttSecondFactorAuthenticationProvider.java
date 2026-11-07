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
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Verifies a numeric one-time code, delivered by e-mail or SMS, as the second factor of the signed-in user through
 * {@link VerifyOneTimeCodeUseCase}, which counts the failures against the second-factor lockout, locks after too many,
 * clears the counter on success and records the security events: a locked second factor is rejected even for a
 * correct code. A channel that already signed the user in is refused as a second factor. A correct code answers with
 * the authentication the user already holds plus the second-factor authority of the channel.
 */
@RequiredArgsConstructor
public class OttSecondFactorAuthenticationProvider implements AuthenticationProvider {

    /** Verifies the code. */
    private final VerifyOneTimeCodeUseCase verifyOneTimeCodeUseCase;

    /** Adds the factor authority to an authentication. */
    private final FactorGrantor factorGrantor;

    /** Rules about the session a second factor is presented in. */
    private final PrimaryFactorSession primaryFactorSession;

    /**
     * Verifies the code.
     *
     * @param authentication the {@link OttSecondFactorToken} to verify.
     * @return the authentication the user already holds with the second factor of the channel added.
     * @throws AuthenticationException if the code is wrong, the second factor is locked or the channel is the one that
     *                                 signed the user in.
     */
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final var request = (OttSecondFactorToken) authentication;
        final var primary = request.primary();
        final var result = verifyOneTimeCodeUseCase.execute(request.bindingId(), primary.getName(),
                request.getCredentials(), OttPurpose.SECOND_FACTOR);
        if (result.status() == OttVerificationResult.Status.LOCKED) {
            throw new LockedException("The second factor is locked");
        }
        if (!result.isSuccess()) {
            throw new BadCredentialsException("The code is not valid");
        }
        if (primaryFactorSession.signedInThrough(primary, result.channel())) {
            throw new BadCredentialsException("The channel that signed the user in cannot be the second factor");
        }
        return factorGrantor.grant(primary, OttFactors.secondFactorAuthority(result.channel()));
    }

    /**
     * Tells which requests this provider verifies.
     *
     * @param authentication the type of the request.
     * @return {@code true} for an {@link OttSecondFactorToken}.
     */
    @Override
    public boolean supports(final Class<?> authentication) {
        return OttSecondFactorToken.class.isAssignableFrom(authentication);
    }
}
