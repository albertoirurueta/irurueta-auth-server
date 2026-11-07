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
package com.irurueta.authserver.authorization.application.social;

import com.irurueta.authserver.authorization.domain.social.FederatedLinkingPolicy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Exposes the domain's {@link FederatedLinkingPolicy} as a bean, so the use cases of social login depend on the policy
 * instead of creating it, and a deployment can replace it with a policy of its own.
 */
@Configuration(proxyBeanMethods = false)
public class SocialConfiguration {

    /**
     * Builds the linking policy.
     *
     * @return the policy every use case of social login applies.
     */
    @Bean
    public FederatedLinkingPolicy federatedLinkingPolicy() {
        return new FederatedLinkingPolicy();
    }
}
