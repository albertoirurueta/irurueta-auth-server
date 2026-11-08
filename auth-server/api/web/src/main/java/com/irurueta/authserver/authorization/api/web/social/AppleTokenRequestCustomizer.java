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
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;

// tag::social-apple-token-request[]
/**
 * Customizes the parameters of the token request of the authorization code grant: the request made for Apple's client
 * id carries the signed JWT of {@link AppleClientSecretGenerator} as its {@code client_secret}, in place of the empty
 * secret the registration holds. Requests of other registrations are left alone. It is the
 * {@code parametersCustomizer} of the framework's token response client, which runs after the parameters are built.
 */
@RequiredArgsConstructor
public class AppleTokenRequestCustomizer implements Consumer<MultiValueMap<String, String>> {

    /** Client id of the Apple registration. */
    private final String appleClientId;

    /** Generates the client secret. */
    private final AppleClientSecretGenerator secretGenerator;

    /**
     * Replaces the client secret of an Apple request.
     *
     * @param parameters the parameters of the token request.
     */
    @Override
    public void accept(final MultiValueMap<String, String> parameters) {
        if (appleClientId.equals(parameters.getFirst(OAuth2ParameterNames.CLIENT_ID))) {
            parameters.set(OAuth2ParameterNames.CLIENT_SECRET, secretGenerator.generate());
        }
    }
}
// end::social-apple-token-request[]
