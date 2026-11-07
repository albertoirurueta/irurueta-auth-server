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

package com.irurueta.authserver.authorization.infrastructure.sms;

import com.irurueta.authserver.authorization.domain.sms.SmsSender;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Wires the Twilio sender when the {@code twilio} profile is active (and SNS is not, so that never two
 * {@link SmsSender} beans exist).
 */
@Configuration(proxyBeanMethods = false)
@Profile("twilio & !sns")
@EnableConfigurationProperties(TwilioProperties.class)
public class TwilioConfiguration {

    /**
     * Creates the SDK wrapper.
     *
     * @param properties credentials and sender, from the environment.
     * @return the client.
     */
    @Bean
    public TwilioMessageClient twilioMessageClient(final TwilioProperties properties) {
        return new TwilioMessageClient(properties);
    }

    /**
     * Creates the sender.
     *
     * @param client SDK wrapper.
     * @return the Twilio sender.
     */
    @Bean
    public SmsSender twilioSmsSender(final TwilioMessageClient client) {
        return new TwilioSmsSender(client);
    }
}
