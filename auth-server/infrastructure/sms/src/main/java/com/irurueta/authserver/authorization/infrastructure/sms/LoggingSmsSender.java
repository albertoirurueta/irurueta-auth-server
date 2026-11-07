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
import com.irurueta.authserver.authorization.domain.sms.SmsSender;
import java.time.Clock;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Default {@link SmsSender}: sends nothing, it records the message in the {@link SmsOutbox} and logs the masked
 * recipient. The text (which carries a one-time code) is never logged at INFO.
 */
@Slf4j
@RequiredArgsConstructor
public class LoggingSmsSender implements SmsSender {

    /** Number of trailing digits of the recipient that are logged. */
    static final int VISIBLE_DIGITS = 4;

    /** Records the messages. */
    private final SmsOutbox outbox;

    /** Source of the recording instant. */
    private final Clock clock;

    @Override
    public void send(final PhoneNumber to, final String text) {
        outbox.add(new SentSms(to, text, clock.instant()));
        final var digits = to.e164();
        log.info("SMS not sent (logging sender), recorded for the development inbox: to=***{}",
                digits.substring(digits.length() - VISIBLE_DIGITS));
    }
}
