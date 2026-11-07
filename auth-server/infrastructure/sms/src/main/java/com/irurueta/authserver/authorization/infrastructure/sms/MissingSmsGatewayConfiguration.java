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

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Stops the startup when no SMS gateway is configured: none of the profiles that provide an {@code SmsSender}
 * ({@code twilio}, {@code sns}, or {@code dev} / {@code test} for the logging one) is active. Without it the startup
 * would still fail, on the missing bean, but with a message that does not say what to do; and the logging sender is
 * deliberately never the default, so that a deployment cannot silently keep its messages in memory.
 */
@Configuration(proxyBeanMethods = false)
@Profile(MissingSmsGatewayConfiguration.NO_SENDER_PROFILES)
public class MissingSmsGatewayConfiguration implements InitializingBean {

    /** Profiles under which no sender is defined. */
    public static final String NO_SENDER_PROFILES = "!dev & !test & !twilio & !sns";

    /** Message of the startup failure. */
    static final String MESSAGE = "No SMS gateway is configured: activate the 'twilio' or 'sns' profile (or 'dev' / "
            + "'test' for the logging sender that keeps the messages in memory)";

    /**
     * Refuses to start.
     *
     * @throws IllegalStateException always, naming the profiles that provide a sender.
     */
    @Override
    public void afterPropertiesSet() {
        throw new IllegalStateException(MESSAGE);
    }
}
