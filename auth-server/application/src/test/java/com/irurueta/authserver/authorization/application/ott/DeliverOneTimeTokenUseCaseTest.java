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
package com.irurueta.authserver.authorization.application.ott;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import com.irurueta.authserver.authorization.application.sms.SmsRequested;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttDelivery;
import com.irurueta.authserver.authorization.domain.ott.OttDeliveryException;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsDeliveryException;
import com.irurueta.authserver.authorization.domain.sms.SmsSender;
import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link DeliverOneTimeTokenUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class DeliverOneTimeTokenUseCaseTest {

    /** Address used by the tests. */
    private static final String ADDRESS = "alice@example.test";

    /** Validity used by the tests. */
    private static final Duration VALID_FOR = Duration.ofMinutes(10);

    /** Destination of the text messages. */
    private static final PhoneNumber TO = new PhoneNumber("+34600000000");

    /** Port that delivers e-mail. */
    @Mock
    private OttDelivery ottDelivery;

    /** Port that sends text messages. */
    @Mock
    private SmsSender smsSender;

    /** Use case under test. */
    @InjectMocks
    private DeliverOneTimeTokenUseCase useCase;

    /**
     * Verifies that a code is e-mailed through the delivery port.
     */
    @Test
    void deliverEmailCode_whenCalled_mailsTheCode() {
        useCase.deliverEmailCode(new EmailCodeRequested(ADDRESS, "123456", VALID_FOR));

        verify(ottDelivery).deliverCode(OttChannel.EMAIL, ADDRESS, "123456", VALID_FOR);
    }

    /**
     * Verifies that a link is e-mailed through the delivery port.
     */
    @Test
    void deliverEmailLink_whenCalled_mailsTheLink() {
        final var link = URI.create("https://auth.example.test/login/ott/confirm?token=t");

        useCase.deliverEmailLink(new EmailLinkRequested(ADDRESS, link, VALID_FOR));

        verify(ottDelivery).deliverLink(OttChannel.EMAIL, ADDRESS, link, VALID_FOR);
    }

    /**
     * Verifies that a text message is sent through the sender.
     */
    @Test
    void deliverSms_whenCalled_sendsTheMessage() {
        useCase.deliverSms(new SmsRequested(TO, "text"));

        verify(smsSender).send(TO, "text");
    }

    /**
     * Verifies that a delivery failure reaches the caller as is, so that it can record it.
     */
    @Test
    void deliverEmailCode_whenTheMailServerFails_propagatesTheFailure() {
        final var failure = new OttDeliveryException("mail is down", new IllegalStateException());
        doThrow(failure).when(ottDelivery).deliverCode(OttChannel.EMAIL, ADDRESS, "123456", VALID_FOR);

        final var thrown = assertThrows(OttDeliveryException.class,
                () -> useCase.deliverEmailCode(new EmailCodeRequested(ADDRESS, "123456", VALID_FOR)));

        assertSame(failure, thrown);
    }

    /**
     * Verifies that a gateway failure reaches the caller as is, so that it can record it.
     */
    @Test
    void deliverSms_whenTheGatewayFails_propagatesTheFailure() {
        final var failure = new SmsDeliveryException("provider down", new IllegalStateException());
        doThrow(failure).when(smsSender).send(TO, "text");

        final var thrown = assertThrows(SmsDeliveryException.class,
                () -> useCase.deliverSms(new SmsRequested(TO, "text")));

        assertSame(failure, thrown);
    }
}
