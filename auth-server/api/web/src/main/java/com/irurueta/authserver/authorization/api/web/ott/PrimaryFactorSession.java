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

import com.irurueta.authserver.authorization.api.web.mfa.AuthenticationFactorRegistry;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Rules about the session a one-time token is used as a second factor in: it must already hold a primary factor, and
 * the second factor must not be the very channel that signed the user in (an e-mail code after an e-mail sign-in
 * would prove the same mailbox twice).
 */
@RequiredArgsConstructor
public class PrimaryFactorSession {

    /** Registry that tells the strength of each factor authority. */
    private final AuthenticationFactorRegistry factorRegistry;

    /**
     * Tells whether an authentication is a signed-in user who presented a primary factor.
     *
     * @param authentication the authentication, or {@code null}.
     * @return {@code true} when it holds a factor of strength {@link FactorStrength#PRIMARY} or
     *         {@link FactorStrength#PRIMARY_STRONG}.
     */
    public boolean holdsPrimaryFactor(final Authentication authentication) {
        return OttGenerationParameters.isSignedIn(authentication)
                && factorRegistry.factorsOf(authentication).stream()
                .anyMatch(factor -> factor.strength() == FactorStrength.PRIMARY
                        || factor.strength() == FactorStrength.PRIMARY_STRONG);
    }

    /**
     * Tells whether a channel is the one that signed the user in.
     *
     * @param authentication the authentication of the session.
     * @param channel        the channel of the second factor.
     * @return {@code true} when the authentication holds the sign-in authority of the channel.
     */
    public boolean signedInThrough(final Authentication authentication, final OttChannel channel) {
        final var authority = OttFactors.signInAuthority(channel);
        return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).anyMatch(authority::equals);
    }
}
