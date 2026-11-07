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
package com.irurueta.authserver.authorization;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.sms.SmsSender;
import com.irurueta.authserver.authorization.infrastructure.sms.LoggingSmsSender;
import com.irurueta.authserver.authorization.infrastructure.sms.MissingSmsGatewayConfiguration;
import com.irurueta.authserver.authorization.infrastructure.sms.SmsAdapterConfiguration;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Checks which {@link SmsSender} the profiles select: the logging one only under {@code dev} or {@code test}, none
 * under a gateway profile (whose own configuration then provides it), and a failed startup with a message that names
 * the profiles when none of them is active. It starts a minimal Spring context (the two configurations of the SMS
 * adapter), hence an integration test.
 */
class SmsSenderProfilesIT {

    /** Runner of a context holding only the configurations of the SMS adapter that the profiles choose between. */
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(SmsAdapterConfiguration.class, MissingSmsGatewayConfiguration.class)
            .withBean(Clock.class, Clock::systemUTC);

    /**
     * Verifies that the {@code test} profile gets the logging sender.
     */
    @Test
    void smsSender_whenTestProfileIsActive_isTheLoggingSender() {
        runner.withPropertyValues("spring.profiles.active=test")
                .run(context -> assertInstanceOf(LoggingSmsSender.class, context.getBean(SmsSender.class)));
    }

    /**
     * Verifies that the {@code dev} profile gets the logging sender.
     */
    @Test
    void smsSender_whenDevProfileIsActive_isTheLoggingSender() {
        runner.withPropertyValues("spring.profiles.active=dev")
                .run(context -> assertInstanceOf(LoggingSmsSender.class, context.getBean(SmsSender.class)));
    }

    /**
     * Verifies that a gateway profile, even next to {@code dev}, leaves the sender to the gateway's configuration and
     * does not stop the startup.
     */
    @Test
    void smsSender_whenGatewayProfileIsActive_isNotTheLoggingSender() {
        runner.withPropertyValues("spring.profiles.active=dev,twilio")
                .run(context -> {
                    assertNull(context.getStartupFailure(), "The startup must not fail");
                    assertTrue(context.getBeansOfType(SmsSender.class).isEmpty());
                });
    }

    /**
     * Verifies that without any profile that provides a sender the startup fails, saying which profiles to activate.
     */
    @Test
    void startup_whenNoSenderProfileIsActive_failsNamingTheProfiles() {
        runner.run(context -> {
            final var failure = context.getStartupFailure();
            assertNotNull(failure, "The startup must fail");
            var cause = (Throwable) failure;
            while (cause.getCause() != null) {
                cause = cause.getCause();
            }
            assertInstanceOf(IllegalStateException.class, cause);
            assertTrue(cause.getMessage().contains("'twilio' or 'sns'"), cause.getMessage());
        });
    }
}
