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

import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.sms.HasVerifiedPhoneUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import java.util.EnumSet;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

// tag::ott-second-factor-channels[]
/**
 * Decides through which channels a one-time code or link may be the second factor of a signed-in user. The same rule
 * decides what the second-factor page offers, whether a requested token is delivered at all and whether a presented
 * one is accepted, so a channel that is not offered can neither be asked for nor used by posting the forms by hand:
 * <ul>
 * <li>never the channel that signed the user in (the same mailbox or phone would be proved twice);</li>
 * <li>SMS only to a user with a verified phone;</li>
 * <li>e-mail only to a user without any other confirmed second factor (authenticator app, passkey, verified phone).
 * The password is reset by e-mail too, so a mailbox is not independent from the password: whoever controls it could
 * otherwise skip the stronger factor the user enrolled. For a user whose multi-factor authentication was forced by an
 * administrator before any factor was enrolled, the e-mail is then the only second factor available.</li>
 * </ul>
 */
@Component
@RequiredArgsConstructor
public class OttSecondFactorChannels {

    /** Rules about the session a second factor is presented in. */
    private final PrimaryFactorSession primaryFactorSession;

    /** Resolves the identifier of the account of the signed-in user. */
    private final SecondFactorUserResolver userResolver;

    /** Tells whether the user has a confirmed second factor of any kind. */
    private final HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Tells whether the user has a verified phone. */
    private final HasVerifiedPhoneUseCase hasVerifiedPhoneUseCase;

    /**
     * Gets the channels a signed-in user may use as the second factor.
     *
     * @param authentication the authentication of the session, which holds a primary factor.
     * @return the channels; empty when none may be used.
     */
    public Set<OttChannel> allowed(final Authentication authentication) {
        final var userId = userResolver.userIdOf(authentication.getName());
        final var channels = EnumSet.noneOf(OttChannel.class);
        if (!primaryFactorSession.signedInThrough(authentication, OttChannel.EMAIL)
                && !hasConfirmedSecondFactorUseCase.execute(userId)) {
            channels.add(OttChannel.EMAIL);
        }
        if (!primaryFactorSession.signedInThrough(authentication, OttChannel.SMS)
                && hasVerifiedPhoneUseCase.execute(userId)) {
            channels.add(OttChannel.SMS);
        }
        return channels;
    }

    /**
     * Tells whether a signed-in user may use a channel as the second factor.
     *
     * @param authentication the authentication of the session, which holds a primary factor.
     * @param channel        the channel.
     * @return {@code true} when the channel is one of {@link #allowed(Authentication)}.
     */
    public boolean isAllowed(final Authentication authentication, final OttChannel channel) {
        return allowed(authentication).contains(channel);
    }
}
// end::ott-second-factor-channels[]
