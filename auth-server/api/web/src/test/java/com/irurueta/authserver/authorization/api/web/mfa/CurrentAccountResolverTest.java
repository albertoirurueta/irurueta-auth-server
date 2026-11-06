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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Unit tests of {@link CurrentAccountResolver}.
 */
@ExtendWith(MockitoExtension.class)
class CurrentAccountResolverTest {

    /** Resolves the identifier of an account. */
    @Mock
    private SecondFactorUserResolver secondFactorUserResolver;

    /** Resolver under test. */
    @InjectMocks
    private CurrentAccountResolver resolver;

    /**
     * Clears the request context the tests bind.
     */
    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    /**
     * Verifies that the account is that of the principal of the current request.
     */
    @Test
    void resolve_whenRequestHasPrincipal_returnsItsAccount() {
        final var id = UUID.randomUUID();
        final var request = new MockHttpServletRequest();
        final Principal principal = () -> "alice";
        request.setUserPrincipal(principal);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        when(secondFactorUserResolver.userIdOf("alice")).thenReturn(id);

        assertEquals(new CurrentAccount(id, "alice"), resolver.resolve());
    }
}
