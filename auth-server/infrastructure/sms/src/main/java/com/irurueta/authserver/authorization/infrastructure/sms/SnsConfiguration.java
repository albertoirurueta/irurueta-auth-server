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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.sns.SnsClient;

/**
 * Wires the Amazon SNS sender when the {@code sns} profile is active. Region and credentials come from the AWS
 * default provider chains (environment, profile, instance role); nothing is configured here.
 */
@Configuration(proxyBeanMethods = false)
@Profile("sns")
public class SnsConfiguration {

    /**
     * Creates the SNS client.
     *
     * @return a client using the default region and credentials chains.
     */
    @Bean
    public SnsClient snsClient() {
        return SnsClient.builder().httpClient(UrlConnectionHttpClient.create()).build();
    }

    /**
     * Creates the sender.
     *
     * @param client SNS client.
     * @return the SNS sender.
     */
    @Bean
    public SmsSender snsSmsSender(final SnsClient client) {
        return new SnsSmsSender(client);
    }
}
