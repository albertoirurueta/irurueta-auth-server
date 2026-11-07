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

package com.irurueta.authserver.authorization.application.sms;

import com.irurueta.authserver.authorization.domain.sms.PhoneCountryResolver;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsCostLedgerRepository;
import com.irurueta.authserver.authorization.domain.sms.SmsCostPolicy;
import java.time.Clock;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Requests an SMS inside the cost policy: the country must be served and the spending of the window and of the day,
 * including this message, must stay within their caps.
 *
 * <p>The cost is reserved by {@link SmsCostLedgerRepository#tryRecord}, which checks both caps and records the message
 * in one atomic step, so concurrent senders cannot overshoot a budget and a refused message costs nothing. The message
 * itself is not sent here: an {@link SmsRequested} event is published and sent after the transaction commits, off the
 * request thread, so the gateway is never called inside a transaction and a rolled-back request sends nothing. A
 * refusal does not roll the surrounding transaction back ({@code noRollbackFor}): this use case is joined by its
 * callers, and a rollback-only mark here would undo what they saved.
 */
@Service
@Transactional(noRollbackFor = SmsRefusedException.class)
@RequiredArgsConstructor
public class SendSmsOneTimeCodeUseCase {

    /** Port that finds the country of a number. */
    private final PhoneCountryResolver phoneCountryResolver;

    /** Policy of countries, costs and caps. */
    private final SmsCostPolicy smsCostPolicy;

    /** Port that records the spend. */
    private final SmsCostLedgerRepository smsCostLedgerRepository;

    /** Publishes the request to send the message. */
    private final ApplicationEventPublisher eventPublisher;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Reserves the cost of a message and requests it.
     *
     * @param to   destination number.
     * @param text text of the message.
     * @throws SmsCountryNotAllowedException if the country of the number is unknown or not served.
     * @throws SmsBudgetExceededException    if the message would exceed the cap of the window or of the day.
     */
    public void execute(final PhoneNumber to, final String text) {
        final var country = phoneCountryResolver.countryOf(to)
                .filter(smsCostPolicy::isCountryAllowed)
                .orElseThrow(SmsCountryNotAllowedException::new);
        if (!smsCostLedgerRepository.tryRecord(clock.instant(), country, smsCostPolicy.costMicros(country),
                smsCostPolicy.windowCap(), smsCostPolicy.dailyCap())) {
            throw new SmsBudgetExceededException();
        }
        eventPublisher.publishEvent(new SmsRequested(to, text));
    }
}
