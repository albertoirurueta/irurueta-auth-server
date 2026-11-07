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

import com.irurueta.authserver.authorization.application.sms.SmsRequested;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttDelivery;
import com.irurueta.authserver.authorization.domain.sms.SmsSender;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Delivers what the one-time token use cases asked for: an e-mailed code or link, or a text message whose cost was
 * already recorded. It is called once the transaction that stored the token has committed, off the request thread,
 * and it runs outside any transaction ({@link Propagation#NOT_SUPPORTED}) because it only calls remote services: a
 * transaction would hold a database connection for as long as the mail server or the SMS gateway takes. A failure is
 * thrown to the caller, which records it; it never reaches the response of the request that asked for the token.
 */
@Service
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@RequiredArgsConstructor
public class DeliverOneTimeTokenUseCase {

    /** Port that delivers e-mail. */
    private final OttDelivery ottDelivery;

    /** Port that sends text messages. */
    private final SmsSender smsSender;

    /**
     * E-mails a code.
     *
     * @param request what to deliver.
     * @throws com.irurueta.authserver.authorization.domain.ott.OttDeliveryException if the mail could not be delivered.
     */
    public void deliverEmailCode(final EmailCodeRequested request) {
        ottDelivery.deliverCode(OttChannel.EMAIL, request.address(), request.code(), request.validFor());
    }

    /**
     * E-mails a magic link.
     *
     * @param request what to deliver.
     * @throws com.irurueta.authserver.authorization.domain.ott.OttDeliveryException if the mail could not be delivered.
     */
    public void deliverEmailLink(final EmailLinkRequested request) {
        ottDelivery.deliverLink(OttChannel.EMAIL, request.address(), request.link(), request.validFor());
    }

    /**
     * Sends a text message.
     *
     * @param request what to send.
     * @throws com.irurueta.authserver.authorization.domain.sms.SmsDeliveryException if the gateway failed or refused
     *         the message.
     */
    public void deliverSms(final SmsRequested request) {
        smsSender.send(request.to(), request.text());
    }
}
