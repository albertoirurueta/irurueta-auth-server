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

package com.irurueta.authserver.authorization.api.web.mfa;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Records the authentications of users as security events: a success as {@link SecurityEventType#LOGIN_SUCCESS} and a
 * failure as {@link SecurityEventType#LOGIN_FAILURE}. Authentications that are not a user signing in (OAuth2 client
 * authentication and bearer tokens of the API) are not recorded. Only the name presented and the type of the failure
 * are stored, never credentials nor the message of the exception.
 */
@Component
@RequiredArgsConstructor
public class SecurityEventAuthenticationEventPublisher implements AuthenticationEventPublisher {

    /** Records the events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    @Override
    public void publishAuthenticationSuccess(final Authentication authentication) {
        if (isUserAuthentication(authentication)) {
            recordSecurityEventUseCase.execute(SecurityEventType.LOGIN_SUCCESS, null, nameOf(authentication), null);
        }
    }

    @Override
    public void publishAuthenticationFailure(final AuthenticationException exception,
            final Authentication authentication) {
        if (isUserAuthentication(authentication)) {
            recordSecurityEventUseCase.execute(SecurityEventType.LOGIN_FAILURE, null, nameOf(authentication),
                    exception.getClass().getSimpleName());
        }
    }

    /**
     * Tells whether an authentication is a user signing in.
     *
     * @param authentication the authentication.
     * @return {@code false} for a client authentication or a bearer token.
     */
    private static boolean isUserAuthentication(final Authentication authentication) {
        return !(authentication instanceof OAuth2ClientAuthenticationToken
                || authentication instanceof BearerTokenAuthenticationToken
                || authentication instanceof AbstractOAuth2TokenAuthenticationToken<?>);
    }

    /**
     * Gets the name the user presented.
     *
     * @param authentication the authentication.
     * @return the name, or {@code null} when blank.
     */
    private static String nameOf(final Authentication authentication) {
        final var name = authentication.getName();
        return StringUtils.hasText(name) ? name : null;
    }
}
