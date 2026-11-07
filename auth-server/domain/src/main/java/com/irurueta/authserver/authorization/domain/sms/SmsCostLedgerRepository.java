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
package com.irurueta.authserver.authorization.domain.sms;

import java.time.Instant;

/**
 * Port that keeps the ledger of what text messages cost, in the database so that a restart cannot reset a budget.
 */
public interface SmsCostLedgerRepository {

    /**
     * Records a message only when it keeps the spend within both caps, atomically: of concurrent callers, the ones
     * whose messages would together exceed a cap are refused, so a budget is never overshot. Nothing is recorded for a
     * refused message. It runs in the caller's transaction and the reservation is kept only if that transaction
     * commits.
     *
     * @param sentAt     instant of the message.
     * @param country    ISO 3166-1 alpha-2 code of the destination country.
     * @param costMicros cost of the message, in millionths of the budget currency.
     * @param windowCap  cap of the short window that ends at {@code sentAt}.
     * @param dailyCap   cap of the day that ends at {@code sentAt}.
     * @return {@code true} when the message was recorded; {@code false} when it would exceed a cap.
     */
    boolean tryRecord(Instant sentAt, String country, long costMicros, SmsSpendCap windowCap, SmsSpendCap dailyCap);

    /**
     * Deletes the entries older than an instant.
     *
     * @param before instant before which entries are no longer needed.
     * @return the number of deleted entries.
     */
    int deleteOlderThan(Instant before);
}
