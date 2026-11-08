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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Unit tests of {@link AppleAuthorizationRequestCustomizer}.
 */
class AppleAuthorizationRequestCustomizerTest {

    /** Client id of Apple. */
    private static final String APPLE_CLIENT_ID = "com.example.service";

    /** Customizer under test. */
    private final AppleAuthorizationRequestCustomizer customizer =
            new AppleAuthorizationRequestCustomizer(APPLE_CLIENT_ID);

    /**
     * Verifies that the request for Apple's client id asks for the form post response.
     */
    @Test
    void accept_whenRequestIsForApple_asksForFormPost() {
        final var builder = builder(APPLE_CLIENT_ID);

        customizer.accept(builder);

        assertEquals("form_post", builder.build().getAdditionalParameters().get("response_mode"));
    }

    /**
     * Verifies that a request for another client is left alone.
     */
    @Test
    void accept_whenRequestIsForAnotherClient_addsNothing() {
        final var builder = builder("other");

        customizer.accept(builder);

        assertFalse(builder.build().getAdditionalParameters().containsKey("response_mode"));
    }

    /**
     * Builds an authorization request for a client.
     *
     * @param clientId client id.
     * @return the builder.
     */
    private static OAuth2AuthorizationRequest.Builder builder(final String clientId) {
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://appleid.apple.com/auth/authorize")
                .clientId(clientId)
                .redirectUri("https://example.org/callback")
                .state("state");
    }
}
