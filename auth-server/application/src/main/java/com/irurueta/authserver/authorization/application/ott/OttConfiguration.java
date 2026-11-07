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

package com.irurueta.authserver.authorization.application.ott;

import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeGenerator;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeHasher;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import java.security.SecureRandom;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Declares the collaborators of the one-time-code use cases as beans, so they can be replaced and mocked.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OttProperties.class)
public class OttConfiguration {

    /**
     * Builds the policy of the one-time codes.
     *
     * @param properties the settings.
     * @return the policy.
     */
    @Bean
    public OttPolicy ottPolicy(final OttProperties properties) {
        return new OttPolicy(properties.codeLength(), properties.codeTtl(), properties.linkTtl(),
                properties.maxAttempts());
    }

    /**
     * Builds the generator of codes.
     *
     * @return the generator, backed by a {@link SecureRandom}.
     */
    @Bean
    public OneTimeCodeGenerator oneTimeCodeGenerator() {
        return new SecureRandomOneTimeCodeGenerator(new SecureRandom());
    }

    /**
     * Builds the hasher of codes.
     *
     * @return the hasher.
     */
    @Bean
    public OneTimeCodeHasher oneTimeCodeHasher() {
        return new Sha256OneTimeCodeHasher();
    }
}
