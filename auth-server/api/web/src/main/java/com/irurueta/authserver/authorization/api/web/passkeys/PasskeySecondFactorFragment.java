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

package com.irurueta.authserver.authorization.api.web.passkeys;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorFragment;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.application.passkeys.HasConfirmedPasskeyUseCase;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Contributes the "use a passkey" action to the second-factor page. The only data it needs is whether the signed-in
 * user has a passkey at all: the options of the ceremony are asked from the framework endpoint, which, for a signed-in
 * session, only allows the credentials of that user.
 */
@Component
@RequiredArgsConstructor
public class PasskeySecondFactorFragment implements SecondFactorFragment {

    /** Position of the passkey action in the second-factor page: after the TOTP forms. */
    public static final int ORDER = 200;

    /** Model attribute telling the fragment whether the user has a passkey to present. */
    public static final String AVAILABLE_ATTRIBUTE = "passkeysAvailable";

    /** Resolves the identifier of the account of the signed-in user. */
    private final SecondFactorUserResolver userResolver;

    /** Tells whether the user has a registered passkey. */
    private final HasConfirmedPasskeyUseCase hasConfirmedPasskeyUseCase;

    /**
     * Gets the template that holds the fragment.
     *
     * @return {@code passkeys-second-factor}.
     */
    @Override
    public String templateName() {
        return "passkeys-second-factor";
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
     * Tells the template whether to offer the passkey.
     *
     * @param authentication the authentication of the user the page is rendered for.
     * @return the model attributes; none when nobody is signed in.
     */
    @Override
    public Map<String, Object> modelAttributes(final Authentication authentication) {
        if (!MfaAuthorizationManager.isUser(authentication)) {
            return Map.of();
        }
        return Map.of(AVAILABLE_ATTRIBUTE,
                hasConfirmedPasskeyUseCase.execute(userResolver.userIdOf(authentication.getName())));
    }
}
