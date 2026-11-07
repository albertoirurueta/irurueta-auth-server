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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsDeliveryException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;

/** Unit tests of {@link SnsSmsSender}. */
@ExtendWith(MockitoExtension.class)
class SnsSmsSenderTest {

    /** Test fixture. */
    private static final PhoneNumber TO = new PhoneNumber("+34612345678");

    /** Test fixture. */
    @Mock
    private SnsClient client;

    /** Test fixture. */
    @InjectMocks
    private SnsSmsSender sender;

    /** The request carries the E.164 number and the text. */
    @Test
    void send_whenGatewaySucceeds_publishesRequest() {
        final var captor = ArgumentCaptor.<PublishRequest>captor();

        sender.send(TO, "hello");

        verify(client).publish(captor.capture());
        assertEquals("+34612345678", captor.getValue().phoneNumber());
        assertEquals("hello", captor.getValue().message());
    }

    /** An SDK failure becomes a generic delivery exception. */
    @Test
    void send_whenGatewayFails_throwsSmsDeliveryExceptionWithoutDetails() {
        when(client.publish(org.mockito.ArgumentMatchers.any(PublishRequest.class)))
                .thenThrow(SdkClientException.create("boom +34612345678"));

        final var error = assertThrows(SmsDeliveryException.class, () -> sender.send(TO, "hello"));

        assertEquals(SnsSmsSender.FAILURE_MESSAGE, error.getMessage());
        assertFalse(error.getMessage().contains("612345678"));
    }
}
