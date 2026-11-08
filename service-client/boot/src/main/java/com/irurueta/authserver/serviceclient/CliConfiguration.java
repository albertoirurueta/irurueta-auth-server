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


package com.irurueta.authserver.serviceclient;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Beans of the {@code client-credentials} and {@code token-exchange} runners, present only under those profiles.
 */
@Configuration(proxyBeanMethods = false)
@Profile({ClientCredentialsCli.PROFILE, TokenExchangeCli.PROFILE})
@EnableConfigurationProperties(CliProperties.class)
public class CliConfiguration {

    /**
     * Output of the runners: the standard output.
     *
     * @return the output.
     */
    @Bean
    CliOutput cliOutput() {
        return new CliOutput(System.out);
    }
}
