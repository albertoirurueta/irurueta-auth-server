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

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsCostLedgerRepository;
import com.irurueta.authserver.authorization.domain.sms.SmsCostPolicy;
import com.irurueta.authserver.authorization.domain.sms.SmsDeliveryException;
import com.irurueta.authserver.authorization.domain.sms.SmsSender;
import java.time.Clock;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Sends an SMS to a number inside the cost policy: the country must be served and the spending of the window and of
 * the day, including this message, must stay within their caps.
 *
 * <p>The spend is read first with zero-cost ledger rows, which add nothing, and the message is recorded only once it
 * passes both caps, so a refused message costs nothing. A refusal or a delivery failure does not roll the
 * surrounding transaction back ({@code noRollbackFor}): this use case is joined by its callers, and a rollback-only
 * mark here would undo what they saved.
 */
@Service
@Transactional(noRollbackFor = {SmsRefusedException.class, SmsDeliveryException.class})
@RequiredArgsConstructor
public class SendSmsOneTimeCodeUseCase {

    /** Length of the day cap window. */
    private static final Duration DAY = Duration.ofDays(1);

    /** Port that finds the country of a number. */
    private final PhoneCountryResolver phoneCountryResolver;

    /** Policy of countries, costs and caps. */
    private final SmsCostPolicy smsCostPolicy;

    /** Port that records the spend. */
    private final SmsCostLedgerRepository smsCostLedgerRepository;

    /** Port that sends the message. */
    private final SmsSender smsSender;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Sends a message.
     *
     * @param to   destination number.
     * @param text text of the message.
     * @throws SmsCountryNotAllowedException if the country of the number is unknown or not served.
     * @throws SmsBudgetExceededException    if the message would exceed the cap of the window or of the day.
     * @throws SmsDeliveryException          if the provider fails; propagated as is, callers decide what to do.
     */
    public void execute(final PhoneNumber to, final String text) {
        final var country = phoneCountryResolver.countryOf(to)
                .filter(smsCostPolicy::isCountryAllowed)
                .orElseThrow(SmsCountryNotAllowedException::new);
        final var cost = smsCostPolicy.costMicros(country);
        final var now = clock.instant();
        final var windowSpend = smsCostLedgerRepository.recordAndGetSpend(now, country, 0L, smsCostPolicy.window());
        final var daySpend = smsCostLedgerRepository.recordAndGetSpend(now, country, 0L, DAY);
        if (!smsCostPolicy.isWithinWindowCap(windowSpend + cost) || !smsCostPolicy.isWithinDailyCap(daySpend + cost)) {
            throw new SmsBudgetExceededException();
        }
        smsCostLedgerRepository.recordAndGetSpend(now, country, cost, smsCostPolicy.window());
        smsSender.send(to, text);
    }
}
