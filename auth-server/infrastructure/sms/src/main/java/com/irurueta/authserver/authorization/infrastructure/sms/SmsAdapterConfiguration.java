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

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.irurueta.authserver.authorization.application.sms.PhoneCountryResolver;
import com.irurueta.authserver.authorization.domain.sms.PhoneNormalizer;
import com.irurueta.authserver.authorization.domain.sms.SmsSender;
import java.time.Clock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

// tag::sms-adapters[]
/**
 * Wires the phone normaliser and the default {@link SmsSender}. The profile expressions make the three senders
 * (logging, Twilio, SNS) mutually exclusive in every combination of profiles: the logging one only when neither
 * gateway profile is active, Twilio unless SNS is also active, and SNS whenever it is active.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SmsOutboxProperties.class)
public class SmsAdapterConfiguration {

    /**
     * Creates the phone normaliser.
     *
     * @return the libphonenumber based normaliser.
     */
    @Bean
    public PhoneNormalizer phoneNormalizer() {
        return new LibPhoneNumberNormalizer(PhoneNumberUtil.getInstance());
    }

    /**
     * Creates the resolver of the country of a phone number.
     *
     * @return the libphonenumber based resolver.
     */
    @Bean
    public PhoneCountryResolver phoneCountryResolver() {
        return new LibPhoneNumberCountryResolver(PhoneNumberUtil.getInstance());
    }

    /**
     * Creates the outbox of the logging sender.
     *
     * @param properties outbox settings.
     * @return the outbox, readable by the development inbox.
     */
    @Bean
    @Profile("!twilio & !sns")
    public SmsOutbox smsOutbox(final SmsOutboxProperties properties) {
        return new SmsOutbox(properties.capacity());
    }

    /**
     * Creates the default sender.
     *
     * @param outbox records the messages.
     * @param clock  source of the recording instant.
     * @return the logging sender.
     */
    @Bean
    @Profile("!twilio & !sns")
    public SmsSender loggingSmsSender(final SmsOutbox outbox, final Clock clock) {
        return new LoggingSmsSender(outbox, clock);
    }
}
// end::sms-adapters[]
