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

import com.irurueta.authserver.authorization.api.web.ProtocolChainCustomizer;
import java.util.function.Consumer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Applies the multi-factor policy to {@code /oauth2/authorize}: a user whose client or account requires a second factor
 * and has not presented one is sent to the second-factor page, with the authorize request saved, before any code is
 * issued. The framework's own request validation still runs first.
 */
@RequiredArgsConstructor
public class MfaProtocolChainCustomizer implements ProtocolChainCustomizer {

    /** Manager that applies the policy. */
    private final MfaAuthorizationManager authorizationManager;

    /** Handler of the endpoint's errors, which sends the user to the second-factor page when needed. */
    private final AuthenticationFailureHandler errorResponseHandler;

    /**
     * Customizes the authorization endpoint.
     *
     * @param server configurer of the authorization server.
     */
    @Override
    public void customize(final OAuth2AuthorizationServerConfigurer server) {
        final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> validator =
                new OAuth2AuthorizationCodeRequestAuthenticationValidator().andThen(this::requireSecondFactor);
        server.authorizationEndpoint(endpoint -> endpoint
                .authenticationProviders(providers -> providers.stream()
                        .filter(OAuth2AuthorizationCodeRequestAuthenticationProvider.class::isInstance)
                        .map(OAuth2AuthorizationCodeRequestAuthenticationProvider.class::cast)
                        .forEach(provider -> provider.setAuthenticationValidator(validator)))
                .errorResponseHandler(errorResponseHandler));
    }

    /**
     * Refuses the request when the user still owes a second factor.
     *
     * @param context the authorization request being validated.
     * @throws SecondFactorRequiredException if the policy is not satisfied.
     */
    private void requireSecondFactor(final OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        final Object principal = context.getAuthentication().getPrincipal();
        if (!(principal instanceof Authentication user) || !MfaAuthorizationManager.isUser(user)) {
            return;
        }
        final AuthorizationResult result = authorizationManager.evaluate(user,
                MfaAuthorizationManager.requiresMfa(context.getRegisteredClient()));
        if (!result.isGranted()) {
            throw new SecondFactorRequiredException();
        }
    }
}
