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
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Condition that holds when Sign in with Apple is configured, so the key of its client secret is only parsed and its
 * special handling (the signed client secret, the form post callback) only installed then.
 */
public class AppleProviderCondition implements Condition {

    /**
     * Tells whether Apple is configured.
     *
     * @param context  the condition context.
     * @param metadata metadata of the annotated element.
     * @return {@code true} when Apple's client id has text.
     */
    @Override
    public boolean matches(final ConditionContext context, final AnnotatedTypeMetadata metadata) {
        return SocialProvidersCondition.isConfigured(context.getEnvironment(), IdentityProvider.APPLE);
    }
}
