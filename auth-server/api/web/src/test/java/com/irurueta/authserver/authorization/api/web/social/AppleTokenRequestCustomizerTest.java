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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.util.LinkedMultiValueMap;

/**
 * Unit tests of {@link AppleTokenRequestCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class AppleTokenRequestCustomizerTest {

    /** Client id of Apple. */
    private static final String APPLE_CLIENT_ID = "com.example.service";

    /** Generates the client secret. */
    @Mock
    private AppleClientSecretGenerator secretGenerator;

    /**
     * Verifies that the request made for Apple's client id carries the generated secret in place of the empty one.
     */
    @Test
    void accept_whenRequestIsForApple_replacesTheClientSecret() {
        when(secretGenerator.generate()).thenReturn("signed-jwt");
        final var parameters = new LinkedMultiValueMap<String, String>();
        parameters.set("client_id", APPLE_CLIENT_ID);
        parameters.set("client_secret", "");

        new AppleTokenRequestCustomizer(APPLE_CLIENT_ID, secretGenerator).accept(parameters);

        assertEquals("signed-jwt", parameters.getFirst("client_secret"));
        assertEquals(1, parameters.get("client_secret").size());
    }

    /**
     * Verifies that a request made for another client keeps its own secret.
     */
    @Test
    void accept_whenRequestIsForAnotherClient_leavesTheParametersAlone() {
        final var parameters = new LinkedMultiValueMap<String, String>();
        parameters.set("client_id", "other");

        new AppleTokenRequestCustomizer(APPLE_CLIENT_ID, secretGenerator).accept(parameters);

        assertNull(parameters.getFirst("client_secret"));
        verifyNoInteractions(secretGenerator);
    }
}
