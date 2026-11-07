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

import com.irurueta.authserver.authorization.application.ott.DeliverOneTimeTokenUseCase;
import com.irurueta.authserver.authorization.application.ott.EmailCodeRequested;
import com.irurueta.authserver.authorization.application.ott.EmailLinkRequested;
import com.irurueta.authserver.authorization.application.sms.SmsRequested;
import com.irurueta.authserver.authorization.domain.ott.OttDeliveryException;
import com.irurueta.authserver.authorization.domain.sms.SmsDeliveryException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

// tag::ott-delivery-listener[]
/**
 * Delivers the one-time tokens the use cases asked for, once the transaction that stored them has committed
 * ({@link TransactionPhase#AFTER_COMMIT}; an event published outside a transaction is delivered at once) and off the
 * request thread ({@code @Async}, on Spring Boot's {@code applicationTaskExecutor}). So no mail server or SMS gateway
 * is ever called inside a transaction, a slow one holds no database connection, a rolled-back request sends nothing,
 * and the time the request takes is the same whether or not something is sent, which keeps the latency from telling
 * an existing account from an unknown one. A failure is logged without the address, the number or the token, and
 * never reaches the response.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OttDeliveryListener {

    /** Delivers the tokens. */
    private final DeliverOneTimeTokenUseCase deliverOneTimeTokenUseCase;

    /**
     * E-mails a code.
     *
     * @param event what to deliver.
     */
    @Async
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onEmailCode(final EmailCodeRequested event) {
        try {
            deliverOneTimeTokenUseCase.deliverEmailCode(event);
        } catch (final OttDeliveryException e) {
            log.warn("A one-time code was not delivered by e-mail: {}", e.getClass().getSimpleName());
        }
    }

    /**
     * E-mails a magic link.
     *
     * @param event what to deliver.
     */
    @Async
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onEmailLink(final EmailLinkRequested event) {
        try {
            deliverOneTimeTokenUseCase.deliverEmailLink(event);
        } catch (final OttDeliveryException e) {
            log.warn("A magic link was not delivered: {}", e.getClass().getSimpleName());
        }
    }

    /**
     * Sends a text message.
     *
     * @param event what to send.
     */
    @Async
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onSms(final SmsRequested event) {
        try {
            deliverOneTimeTokenUseCase.deliverSms(event);
        } catch (final SmsDeliveryException e) {
            log.warn("An SMS was not delivered: {}", e.getClass().getSimpleName());
        }
    }
}
// end::ott-delivery-listener[]
