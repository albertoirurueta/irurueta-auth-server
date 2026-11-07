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

import com.irurueta.authserver.authorization.application.sms.SmsProperties;
import com.irurueta.authserver.authorization.domain.ott.ExpiredLinkTokenPurger;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeRepository;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerificationRepository;
import com.irurueta.authserver.authorization.domain.sms.SmsCostLedgerRepository;
import java.time.Clock;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Deletes what the one-time-code and SMS features leave behind: expired codes, expired pending phone verifications,
 * cost ledger rows older than the retention and expired magic-link tokens.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class CleanupOttUseCase {

    /** Port that stores the codes. */
    private final OneTimeCodeRepository oneTimeCodeRepository;

    /** Port that stores the pending phone verifications. */
    private final PhoneVerificationRepository phoneVerificationRepository;

    /** Port that stores the SMS spend. */
    private final SmsCostLedgerRepository smsCostLedgerRepository;

    /** Port that removes the expired magic-link tokens. */
    private final ExpiredLinkTokenPurger expiredLinkTokenPurger;

    /** SMS settings, for the retention of the ledger. */
    private final SmsProperties smsProperties;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Runs the cleanup.
     *
     * @return the number of rows removed from each store.
     */
    public OttCleanupResult execute() {
        final var now = clock.instant();
        return new OttCleanupResult(
                oneTimeCodeRepository.deleteExpired(now),
                phoneVerificationRepository.deleteExpired(now),
                smsCostLedgerRepository.deleteOlderThan(now.minus(smsProperties.ledgerRetention())),
                expiredLinkTokenPurger.deleteExpired(now));
    }
}
