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

package com.irurueta.authserver.serviceclient.device;

import java.time.Clock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.client.RestClient;

/**
 * Beans of the device flow CLI, present only under the {@value #PROFILE} profile.
 */
@Configuration(proxyBeanMethods = false)
@Profile(DeviceFlowConfiguration.PROFILE)
@EnableConfigurationProperties(DeviceFlowProperties.class)
public class DeviceFlowConfiguration {

    /**
     * Name of the Spring profile that turns the CLI on.
     */
    public static final String PROFILE = "device-flow";

    /**
     * Sleeper that really blocks the thread.
     *
     * @return the sleeper.
     */
    @Bean
    public Sleeper deviceFlowSleeper() {
        return Thread::sleep;
    }

    /**
     * Clock used to detect that the device code expired.
     *
     * @return the UTC system clock.
     */
    @Bean
    public Clock deviceFlowClock() {
        return Clock.systemUTC();
    }

    /**
     * Output of the CLI: the standard output.
     *
     * @return the output.
     */
    @Bean
    public DeviceFlowOutput deviceFlowOutput() {
        return new DeviceFlowOutput(System.out);
    }

    /**
     * HTTP client aimed at the authorization server.
     *
     * @param properties the CLI settings.
     * @return the client.
     */
    @Bean
    public RestClient deviceFlowRestClient(final DeviceFlowProperties properties) {
        final var issuer = properties.issuer().toString();
        return RestClient.builder()
                .baseUrl(issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer)
                .build();
    }
}
