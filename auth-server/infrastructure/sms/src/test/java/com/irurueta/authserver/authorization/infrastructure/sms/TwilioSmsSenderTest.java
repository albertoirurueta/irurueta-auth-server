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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsDeliveryException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** Unit tests of {@link TwilioSmsSender}. */
@ExtendWith(MockitoExtension.class)
class TwilioSmsSenderTest {

    /** Test fixture. */
    private static final PhoneNumber TO = new PhoneNumber("+34612345678");

    /** Test fixture. */
    @Mock
    private TwilioMessageClient client;

    /** Test fixture. */
    @InjectMocks
    private TwilioSmsSender sender;

    /** The gateway receives the E.164 number and the text. */
    @Test
    void send_whenGatewaySucceeds_delegatesToClient() {
        sender.send(TO, "hello");

        verify(client).send("+34612345678", "hello");
    }

    /** A gateway failure becomes a generic delivery exception. */
    @Test
    void send_whenGatewayFails_throwsSmsDeliveryExceptionWithoutDetails() {
        doThrow(new IllegalStateException("boom +34612345678 hello")).when(client).send("+34612345678", "hello");

        final var error = assertThrows(SmsDeliveryException.class, () -> sender.send(TO, "hello"));

        assertEquals(TwilioSmsSender.FAILURE_MESSAGE, error.getMessage());
        assertFalse(error.getMessage().contains("612345678"));
    }
}
