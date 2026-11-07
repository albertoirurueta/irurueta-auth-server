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
 * Unit tests of {@link SocialProvidersCondition}.
 */
class SocialProvidersConditionTest {

    /** Condition under test. */
    private final SocialProvidersCondition condition = new SocialProvidersCondition();

    /**
     * Verifies that the condition fails while no provider has a client id.
     */
    @Test
    void matches_whenNoProviderHasAClientId_isFalse() {
        final var environment = new MockEnvironment().withProperty("authserver.social.providers.google.client-id", "");

        assertFalse(condition.matches(context(environment), mock(AnnotatedTypeMetadata.class)));
    }

    /**
     * Verifies that the condition holds when one provider has a client id.
     */
    @Test
    void matches_whenAProviderHasAClientId_isTrue() {
        final var environment = new MockEnvironment()
                .withProperty("authserver.social.providers.github.client-id", "id");

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
