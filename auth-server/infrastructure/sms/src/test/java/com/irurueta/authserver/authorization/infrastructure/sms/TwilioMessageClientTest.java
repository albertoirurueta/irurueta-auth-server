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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;

import com.twilio.http.TwilioRestClient;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.rest.api.v2010.account.MessageCreator;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link TwilioMessageClient}; the SDK's static factory is mocked, no network is used. */
class TwilioMessageClientTest {

    /** Test fixture. */
    private static final String TO = "+34612345678";

    /** Missing credentials are refused. */
    @Test
    void constructor_whenCredentialsMissing_throwsIllegalStateException() {
        final var properties = new TwilioProperties(null, null, "+15005550006", null);
        assertThrows(IllegalStateException.class, () -> new TwilioMessageClient(properties));
    }

    /** A missing sender is refused. */
    @Test
    void constructor_whenNoSenderNorService_throwsIllegalStateException() {
        final var properties = new TwilioProperties("test-sid", "test-token", " ", null);
        assertThrows(IllegalStateException.class, () -> new TwilioMessageClient(properties));
    }

    /** With a sender number the message is created through the SDK. */
    @Test
    void send_whenSenderNumber_createsMessage() {
        final var creator = mock(MessageCreator.class);
        try (var message = mockStatic(Message.class)) {
            message.when(() -> Message.creator(any(com.twilio.type.PhoneNumber.class),
                    any(com.twilio.type.PhoneNumber.class), eq("hello"))).thenReturn(creator);
            final var client = new TwilioMessageClient(
                    new TwilioProperties("test-sid", "test-token", "+15005550006", null));

            client.send(TO, "hello");

            verify(creator).create(any(TwilioRestClient.class));
        }
    }

    /** With a messaging service the message is created through the SDK. */
    @Test
    void send_whenMessagingService_createsMessage() {
        final var creator = mock(MessageCreator.class);
        try (var message = mockStatic(Message.class)) {
            message.when(() -> Message.creator(any(com.twilio.type.PhoneNumber.class), eq("test-service"),
                    eq("hello"))).thenReturn(creator);
            final var client = new TwilioMessageClient(
                    new TwilioProperties("test-sid", "test-token", null, "test-service"));

            client.send(TO, "hello");

            verify(creator).create(any(TwilioRestClient.class));
        }
    }
}
