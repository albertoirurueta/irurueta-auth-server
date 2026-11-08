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
package com.irurueta.authserver.bff.api.web.login;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.StringUtils;

/**
 * Adds the step-up values that {@link BffLoginController} kept in the session to the authorization request built by the
 * delegate, as the OpenID Connect {@code acr_values} and {@code max_age} parameters, and forgets them, so they apply to
 * one login only. Without them the authorization request is the delegate's, unchanged.
 */
@RequiredArgsConstructor
public class StepUpAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    /** Session attribute holding the {@link StepUpLoginParameters} of the next login. */
    public static final String STEP_UP_ATTRIBUTE = StepUpAuthorizationRequestResolver.class.getName() + ".STEP_UP";

    /** Authorization request parameter naming the authentication context classes asked for. */
    static final String ACR_VALUES_PARAMETER = "acr_values";

    /** Authorization request parameter naming the maximum age of the authentication, in seconds. */
    static final String MAX_AGE_PARAMETER = "max_age";

    /** Builds the authorization request. */
    private final OAuth2AuthorizationRequestResolver delegate;

    @Override
    public OAuth2AuthorizationRequest resolve(final HttpServletRequest request) {
        return withStepUp(request, delegate.resolve(request));
    }

    @Override
    public OAuth2AuthorizationRequest resolve(final HttpServletRequest request,
            final String clientRegistrationId) {
        return withStepUp(request, delegate.resolve(request, clientRegistrationId));
    }

    /**
     * Adds the step-up values of the session, if any, to an authorization request and removes them from the session.
     *
     * @param request              the current request.
     * @param authorizationRequest the authorization request of the delegate; {@code null} when the request is not an
     *                             authorization request.
     * @return the authorization request with the step-up parameters, or as it was when the session holds none.
     */
    private static OAuth2AuthorizationRequest withStepUp(final HttpServletRequest request,
            final OAuth2AuthorizationRequest authorizationRequest) {
        if (authorizationRequest == null) {
            return null;
        }
        final var session = request.getSession(false);
        if (session == null || !(session.getAttribute(STEP_UP_ATTRIBUTE) instanceof StepUpLoginParameters stepUp)) {
            return authorizationRequest;
        }
        session.removeAttribute(STEP_UP_ATTRIBUTE);
        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .additionalParameters(parameters -> {
                    if (StringUtils.hasText(stepUp.acrValues())) {
                        parameters.put(ACR_VALUES_PARAMETER, stepUp.acrValues());
                    }
                    if (stepUp.maxAge() != null) {
                        parameters.put(MAX_AGE_PARAMETER, String.valueOf(stepUp.maxAge()));
                    }
                })
                .build();
    }
}
