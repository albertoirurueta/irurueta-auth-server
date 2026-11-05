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
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of the default methods of {@link LoginMethodFragment}.
 */
@ExtendWith(MockitoExtension.class)
class LoginMethodFragmentTest {

    /** Fragment whose default methods run for real and whose abstract methods are stubbed. */
    @Mock(answer = Answers.CALLS_REAL_METHODS)
    private LoginMethodFragment fragment;

    /**
     * Verifies that the reference joins the template name and the fragment name.
     */
    @Test
    void reference_whenCalled_joinsTemplateAndFragment() {
        when(fragment.templateName()).thenReturn("test-fragments");
        when(fragment.fragmentName()).thenReturn("first");

        assertEquals("test-fragments :: first", fragment.reference());
    }
}
