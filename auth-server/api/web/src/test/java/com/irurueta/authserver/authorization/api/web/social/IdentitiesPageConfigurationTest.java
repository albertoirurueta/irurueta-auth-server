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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.Order;

/** Unit tests of {@link IdentitiesPageConfiguration}. */
class IdentitiesPageConfigurationTest {

    /**
     * The configuration declares the customizer with its order.
     *
     * @throws NoSuchMethodException if the bean method does not exist.
     */
    @Test
    void identitiesPageChainCustomizer_whenDeclared_hasTheOrderOfTheCustomizer() throws NoSuchMethodException {
        final var customizer = new IdentitiesPageConfiguration()
                .identitiesPageChainCustomizer(mock(MfaAuthorizationManager.class));

        assertInstanceOf(IdentitiesPageChainCustomizer.class, customizer);
        assertEquals(IdentitiesPageChainCustomizer.ORDER, IdentitiesPageConfiguration.class
                .getMethod("identitiesPageChainCustomizer", MfaAuthorizationManager.class)
                .getAnnotation(Order.class).value());
    }
}
