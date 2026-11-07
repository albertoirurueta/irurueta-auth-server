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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationProvider;

/** Unit tests of {@link OttProviders}. */
class OttProvidersTest {

    /** The record keeps the providers it is given. */
    @Test
    void constructor_whenCreated_keepsTheProviders() {
        final var link = mock(AuthenticationProvider.class);
        final var code = mock(AuthenticationProvider.class);
        final var secondFactor = mock(AuthenticationProvider.class);

        final var providers = new OttProviders(link, code, secondFactor);

        assertSame(link, providers.link());
        assertSame(code, providers.code());
        assertSame(secondFactor, providers.secondFactor());
    }
}
