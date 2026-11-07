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

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsDeliveryException;
import com.irurueta.authserver.authorization.domain.sms.SmsSender;
import lombok.RequiredArgsConstructor;

/**
 * {@link SmsSender} that sends through Twilio. Every failure becomes a {@link SmsDeliveryException} without the
 * recipient or the text.
 */
@RequiredArgsConstructor
public class TwilioSmsSender implements SmsSender {

    /** Generic failure description. */
    static final String FAILURE_MESSAGE = "Twilio could not send the text message";

    /** SDK wrapper. */
    private final TwilioMessageClient client;

    @Override
    public void send(final PhoneNumber to, final String text) {
        try {
            client.send(to.e164(), text);
        } catch (final RuntimeException e) {
            throw new SmsDeliveryException(FAILURE_MESSAGE, e);
        }
    }
}
