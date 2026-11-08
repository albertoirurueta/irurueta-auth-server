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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * Unit tests of {@link AuthMethod}.
 */
class AuthMethodTest {

    /**
     * Verifies that every method maps onto the Spring Security method of the same name.
     */
    @Test
    void getClientAuthenticationMethod_whenAskedForEveryMethod_returnsSpringSecurityMethod() {
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                AuthMethod.CLIENT_SECRET_BASIC.getClientAuthenticationMethod());
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                AuthMethod.PRIVATE_KEY_JWT.getClientAuthenticationMethod());
        assertEquals(ClientAuthenticationMethod.TLS_CLIENT_AUTH,
                AuthMethod.TLS_CLIENT_AUTH.getClientAuthenticationMethod());
        assertEquals(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
                AuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH.getClientAuthenticationMethod());
    }

    /**
     * Verifies that only the two mutual TLS methods report so.
     */
    @Test
    void isMutualTls_whenAskedForEveryMethod_isTrueOnlyForTheMutualTlsOnes() {
        assertFalse(AuthMethod.CLIENT_SECRET_BASIC.isMutualTls());
        assertFalse(AuthMethod.PRIVATE_KEY_JWT.isMutualTls());
        assertTrue(AuthMethod.TLS_CLIENT_AUTH.isMutualTls());
        assertTrue(AuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH.isMutualTls());
    }
}
