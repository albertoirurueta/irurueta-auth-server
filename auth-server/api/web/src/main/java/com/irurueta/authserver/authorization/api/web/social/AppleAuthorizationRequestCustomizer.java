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

package com.irurueta.authserver.authorization.api.web.social;

import java.util.function.Consumer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Customizes the authorization request: Apple only hands over the name and the e-mail address of the user when the
 * response is posted to the redirect URI ({@code response_mode=form_post}), so the request made for Apple's client id
 * asks for it. Requests of other registrations are left alone.
 */
@RequiredArgsConstructor
public class AppleAuthorizationRequestCustomizer implements Consumer<OAuth2AuthorizationRequest.Builder> {

    /** Parameter that tells the provider how to return the response. */
    static final String RESPONSE_MODE = "response_mode";

    /** Value of {@link #RESPONSE_MODE} that makes the provider post the response to the redirect URI. */
    static final String FORM_POST = "form_post";

    /** Client id of the Apple registration. */
    private final String appleClientId;

    /**
     * Adds the response mode to an Apple request.
     *
     * @param builder builder of the authorization request.
     */
    @Override
    public void accept(final OAuth2AuthorizationRequest.Builder builder) {
        if (appleClientId.equals(builder.build().getClientId())) {
            builder.additionalParameters(parameters -> parameters.put(RESPONSE_MODE, FORM_POST));
        }
    }
}
