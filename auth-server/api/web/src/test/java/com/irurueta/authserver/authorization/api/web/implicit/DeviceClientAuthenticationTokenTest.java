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
package com.irurueta.authserver.authorization.api.web.implicit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * Unit tests of {@link DeviceClientAuthenticationToken}.
 */
class DeviceClientAuthenticationTokenTest {

    /**
     * Verifies that the token names the client and uses the {@code none} method, with no credential.
     */
    @Test
    void constructor_whenCreated_namesTheClientWithTheNoneMethod() {
        final var token = new DeviceClientAuthenticationToken("device-client");

        assertEquals("device-client", token.getPrincipal());
        assertEquals("device-client", token.clientId());
        assertEquals(ClientAuthenticationMethod.NONE, token.getClientAuthenticationMethod());
        assertTrue(token.getAdditionalParameters().isEmpty());
    }
}
