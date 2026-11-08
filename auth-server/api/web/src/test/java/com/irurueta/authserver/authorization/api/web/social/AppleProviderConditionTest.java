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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.mock.env.MockEnvironment;

/**
 * Unit tests of {@link AppleProviderCondition}.
 */
class AppleProviderConditionTest {

    /** Condition under test. */
    private final AppleProviderCondition condition = new AppleProviderCondition();

    /**
     * Verifies that another configured provider does not enable Apple.
     */
    @Test
    void matches_whenOnlyAnotherProviderIsConfigured_isFalse() {
        final var environment = new MockEnvironment()
                .withProperty("authserver.social.providers.github.client-id", "id");

        assertFalse(condition.matches(context(environment), mock(AnnotatedTypeMetadata.class)));
    }

    /**
     * Verifies that Apple's client id enables it.
     */
    @Test
    void matches_whenAppleHasAClientId_isTrue() {
        final var environment = new MockEnvironment()
                .withProperty("authserver.social.providers.apple.client-id", "id");

        assertTrue(condition.matches(context(environment), mock(AnnotatedTypeMetadata.class)));
    }

    /**
     * Builds a condition context over an environment.
     *
     * @param environment the environment.
     * @return the context.
     */
    private static ConditionContext context(final MockEnvironment environment) {
        final var context = mock(ConditionContext.class);
        when(context.getEnvironment()).thenReturn(environment);
        return context;
    }
}
