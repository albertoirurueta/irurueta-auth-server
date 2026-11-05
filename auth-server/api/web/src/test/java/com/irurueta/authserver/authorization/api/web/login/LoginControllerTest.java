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

package com.irurueta.authserver.authorization.api.web.login;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ui.ExtendedModelMap;

/**
 * Unit tests of {@link LoginController}.
 */
@ExtendWith(MockitoExtension.class)
class LoginControllerTest {

    /** Name of the model attribute that holds the fragments. */
    private static final String FRAGMENTS = "fragments";

    /** Order of the fragment that is rendered first. */
    private static final int FIRST_ORDER = 10;

    /** Order of the fragment that is rendered second. */
    private static final int SECOND_ORDER = 20;

    /** Fragment that is rendered first. */
    @Mock
    private LoginMethodFragment first;

    /** Fragment that is rendered second. */
    @Mock
    private LoginMethodFragment second;

    /**
     * Verifies that the model holds an empty list when no authentication method contributes a fragment.
     */
    @Test
    void login_whenThereAreNoFragments_putsAnEmptyList() {
        final var model = new ExtendedModelMap();

        final var view = new LoginController(List.of()).login(model);

        assertEquals("login", view);
        assertEquals(LoginController.LOGIN_PATH, model.get(LoginController.LOGIN_PATH_ATTRIBUTE));
        assertTrue(((List<?>) model.get(FRAGMENTS)).isEmpty());
    }

    /**
     * Verifies that the fragments are sorted by their order.
     */
    @Test
    void login_whenThereAreTwoFragments_putsThemSortedByOrder() {
        when(first.order()).thenReturn(FIRST_ORDER);
        when(second.order()).thenReturn(SECOND_ORDER);
        final var model = new ExtendedModelMap();

        new LoginController(List.of(second, first)).login(model);

        assertEquals(List.of(first, second), model.get(FRAGMENTS));
    }
}
