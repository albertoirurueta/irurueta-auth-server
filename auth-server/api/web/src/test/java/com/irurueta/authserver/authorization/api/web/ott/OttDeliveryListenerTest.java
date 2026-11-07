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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import com.irurueta.authserver.authorization.application.ott.DeliverOneTimeTokenUseCase;
import com.irurueta.authserver.authorization.application.ott.EmailCodeRequested;
import com.irurueta.authserver.authorization.application.ott.EmailLinkRequested;
import com.irurueta.authserver.authorization.application.sms.SmsRequested;
import com.irurueta.authserver.authorization.domain.ott.OttDeliveryException;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsDeliveryException;
import java.lang.reflect.Method;
import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/** Unit tests of {@link OttDeliveryListener}. */
@ExtendWith(MockitoExtension.class)
class OttDeliveryListenerTest {

    /** A code to e-mail. */
    private static final EmailCodeRequested EMAIL_CODE =
            new EmailCodeRequested("alice@example.test", "123456", Duration.ofMinutes(10));

    /** A link to e-mail. */
    private static final EmailLinkRequested EMAIL_LINK = new EmailLinkRequested("alice@example.test",
            URI.create("https://auth.example.test/login/ott/confirm?token=t"), Duration.ofMinutes(15));

    /** A text message to send. */
    private static final SmsRequested SMS = new SmsRequested(new PhoneNumber("+34600000000"), "text");

    /** Delivers the tokens. */
    @Mock
    private DeliverOneTimeTokenUseCase deliverOneTimeTokenUseCase;

    /** Listener under test. */
    @InjectMocks
    private OttDeliveryListener listener;

    /** Each event is handed to its delivery. */
    @Test
    void onEvents_whenCalled_deliverThroughTheUseCase() {
        listener.onEmailCode(EMAIL_CODE);
        listener.onEmailLink(EMAIL_LINK);
        listener.onSms(SMS);

        verify(deliverOneTimeTokenUseCase).deliverEmailCode(EMAIL_CODE);
        verify(deliverOneTimeTokenUseCase).deliverEmailLink(EMAIL_LINK);
        verify(deliverOneTimeTokenUseCase).deliverSms(SMS);
    }

    /** A failed delivery is recorded and goes no further. */
    @Test
    void onEvents_whenTheDeliveryFails_swallowTheFailure() {
        final var mailFailure = new OttDeliveryException("mail is down", new IllegalStateException());
        doThrow(mailFailure).when(deliverOneTimeTokenUseCase).deliverEmailCode(EMAIL_CODE);
        doThrow(mailFailure).when(deliverOneTimeTokenUseCase).deliverEmailLink(EMAIL_LINK);
        doThrow(new SmsDeliveryException("provider down", new IllegalStateException()))
                .when(deliverOneTimeTokenUseCase).deliverSms(SMS);

        assertDoesNotThrow(() -> listener.onEmailCode(EMAIL_CODE));
        assertDoesNotThrow(() -> listener.onEmailLink(EMAIL_LINK));
        assertDoesNotThrow(() -> listener.onSms(SMS));
    }

    /**
     * Every handler runs after the commit (or at once without a transaction) and off the request thread.
     *
     * @throws NoSuchMethodException if a handler is missing.
     */
    @Test
    void handlers_whenInspected_runAfterCommitAndAsynchronously() throws NoSuchMethodException {
        for (final var method : new Method[] {
                OttDeliveryListener.class.getMethod("onEmailCode", EmailCodeRequested.class),
                OttDeliveryListener.class.getMethod("onEmailLink", EmailLinkRequested.class),
                OttDeliveryListener.class.getMethod("onSms", SmsRequested.class)}) {
            final var listening = method.getAnnotation(TransactionalEventListener.class);
            assertNotNull(listening);
            assertEquals(TransactionPhase.AFTER_COMMIT, listening.phase());
            assertEquals(Boolean.TRUE, listening.fallbackExecution());
            assertNotNull(method.getAnnotation(Async.class));
        }
    }
}
