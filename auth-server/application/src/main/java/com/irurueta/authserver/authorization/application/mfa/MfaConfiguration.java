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

package com.irurueta.authserver.authorization.application.mfa;

import com.irurueta.authserver.authorization.domain.mfa.MfaPolicy;
import com.irurueta.authserver.authorization.domain.totp.SecretGenerator;
import com.irurueta.authserver.authorization.domain.totp.SecureRandomSecretGenerator;
import com.irurueta.authserver.authorization.domain.totp.TotpAlgorithm;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Exposes the domain collaborators of the multi-factor use cases as beans, so no use case creates them and a
 * deployment (or a test) can replace any of them, and binds the {@link MfaProperties}.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(MfaProperties.class)
public class MfaConfiguration {

    /**
     * Builds the generator of TOTP shared secrets.
     *
     * @return the generator (160-bit secrets from a {@link java.security.SecureRandom}).
     */
    @Bean
    public SecretGenerator secretGenerator() {
        return new SecureRandomSecretGenerator();
    }

    /**
     * Builds the TOTP algorithm (RFC 6238, HMAC-SHA1, 30 seconds, 6 digits).
     *
     * @return the algorithm.
     */
    @Bean
    public TotpAlgorithm totpAlgorithm() {
        return new TotpAlgorithm();
    }

    /**
     * Builds the policy that decides which factors are enough and when a second factor is required.
     *
     * @return the policy.
     */
    @Bean
    public MfaPolicy mfaPolicy() {
        return new MfaPolicy();
    }
}
