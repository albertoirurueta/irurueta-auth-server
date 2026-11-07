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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import java.time.Clock;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link SmsAdapterConfiguration}. */
class SmsAdapterConfigurationTest {

    /** Test fixture. */
    private final SmsAdapterConfiguration configuration = new SmsAdapterConfiguration();

    /** The normaliser bean works. */
    @Test
    void phoneNormalizer_whenCalled_returnsWorkingNormalizer() {
        assertEquals(new PhoneNumber("+34612345678"),
                configuration.phoneNormalizer().normalize("612345678", "ES").orElseThrow());
    }

    /** The outbox uses the configured capacity and the sender is the logging one. */
    @Test
    void loggingSmsSender_whenCalled_returnsLoggingSender() {
        final var outbox = configuration.smsOutbox(new SmsOutboxProperties(0));
        assertInstanceOf(LoggingSmsSender.class, configuration.loggingSmsSender(outbox, Clock.systemUTC()));
    }
}
