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

import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.util.Arrays;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.StringUtils;

/**
 * Condition that holds when at least one social provider is configured, that is, when some
 * {@code authserver.social.providers.<id>.client-id} has text. Every bean of the social login hangs from it, so with
 * no provider configured (the default) the application has no social login at all: no client registration
 * repository (which cannot be empty), no filter and no login page entry.
 */
public class SocialProvidersCondition implements Condition {

    /**
     * Tells whether a provider is configured.
     *
     * @param environment environment to read the setting from.
     * @param provider    the provider.
     * @return {@code true} when the provider's client id has text.
     */
    static boolean isConfigured(final Environment environment, final IdentityProvider provider) {
        return StringUtils.hasText(
                environment.getProperty("authserver.social.providers." + provider.id() + ".client-id"));
    }

    /**
     * Tells whether any provider is configured.
     *
     * @param context  the condition context.
     * @param metadata metadata of the annotated element.
     * @return {@code true} when at least one provider is configured.
     */
    @Override
    public boolean matches(final ConditionContext context, final AnnotatedTypeMetadata metadata) {
        return Arrays.stream(IdentityProvider.values())
                .anyMatch(provider -> isConfigured(context.getEnvironment(), provider));
    }
}
