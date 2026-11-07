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

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorFragment;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

// tag::ott-second-factor-fragment[]
/**
 * Contributes the one-time token second factor to the second-factor page: the buttons that send a code or a magic link
 * by e-mail and a code by SMS to the signed-in user, each posting to {@code POST /ott/generate} with the second-factor
 * purpose. Only the channels {@link OttSecondFactorChannels} allows are offered: never the one that signed the user in,
 * SMS only to a user with a verified phone, and e-mail only to a user without any other confirmed second factor.
 */
@Component
@RequiredArgsConstructor
public class OttSecondFactorFragment implements SecondFactorFragment {

    /** Position of the one-time token action in the second-factor page: after the passkey one. */
    public static final int ORDER = 300;

    /** Model attribute telling the fragment whether to offer the e-mail code and link. */
    public static final String EMAIL_AVAILABLE_ATTRIBUTE = "ottEmailAvailable";

    /** Model attribute telling the fragment whether to offer the SMS code. */
    public static final String SMS_AVAILABLE_ATTRIBUTE = "ottSmsAvailable";

    /** Decides which channels may be the second factor of the user. */
    private final OttSecondFactorChannels secondFactorChannels;

    /**
     * Gets the template that holds the fragment.
     *
     * @return {@code ott-second-factor}.
     */
    @Override
    public String templateName() {
        return "ott-second-factor";
    }

    /**
     * Gets the fragment of the template.
     *
     * @return {@code form}.
     */
    @Override
    public String fragmentName() {
        return "form";
    }

    /**
     * Gets the position of the fragment.
     *
     * @return {@link #ORDER}.
     */
    @Override
    public int order() {
        return ORDER;
    }

    /**
     * Tells the template which channels to offer.
     *
     * @param authentication the authentication of the user the page is rendered for.
     * @return the model attributes; none when nobody is signed in.
     */
    @Override
    public Map<String, Object> modelAttributes(final Authentication authentication) {
        if (!MfaAuthorizationManager.isUser(authentication)) {
            return Map.of();
        }
        final var channels = secondFactorChannels.allowed(authentication);
        return Map.of(
                EMAIL_AVAILABLE_ATTRIBUTE, channels.contains(OttChannel.EMAIL),
                SMS_AVAILABLE_ATTRIBUTE, channels.contains(OttChannel.SMS));
    }
}
// end::ott-second-factor-fragment[]
