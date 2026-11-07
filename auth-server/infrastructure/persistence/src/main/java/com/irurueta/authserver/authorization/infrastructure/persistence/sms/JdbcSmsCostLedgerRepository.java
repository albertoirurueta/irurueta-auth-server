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
package com.irurueta.authserver.authorization.infrastructure.persistence.sms;

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.toTimestamp;

import com.irurueta.authserver.authorization.domain.sms.SmsCostLedgerRepository;
import com.irurueta.authserver.authorization.domain.sms.SmsSpendCap;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link SmsCostLedgerRepository} over the {@code sms_cost_ledger} table. It opens no transaction: a reservation runs
 * in the caller's, where it first takes a PostgreSQL transaction-level advisory lock, so that concurrent senders (of
 * this or another instance) check and record their messages one after the other and a cap is never overshot. The
 * check and the insert are one conditional statement, so a refused message leaves no row. A refusal is logged, without
 * the number or the country, so that an exhausted budget can be seen.
 */
@Slf4j
@Repository
@RequiredArgsConstructor
public class JdbcSmsCostLedgerRepository implements SmsCostLedgerRepository {

    /** Key of the advisory lock that serialises the reservations of SMS spend. */
    static final long SPEND_LOCK_KEY = 5_203_341_870_000_630L;

    /** Statement taking the advisory lock, released when the caller's transaction ends. */
    private static final String LOCK = "SELECT pg_advisory_xact_lock(?)";

    /**
     * Statement inserting a row only when the spend of each window, the new row included, stays within its cap. It
     * runs after the lock is taken, so (in the default {@code READ COMMITTED} isolation) it sees every row a previous
     * holder of the lock committed.
     */
    private static final String INSERT_WITHIN_CAPS = """
            INSERT INTO sms_cost_ledger (sent_at, country, cost_micros)
            SELECT ?::timestamptz, ?::char(2), ?::bigint
            WHERE (SELECT COALESCE(SUM(cost_micros), 0) FROM sms_cost_ledger WHERE sent_at > ?::timestamptz)
                    + ?::bigint <= ?::bigint
              AND (SELECT COALESCE(SUM(cost_micros), 0) FROM sms_cost_ledger WHERE sent_at > ?::timestamptz)
                    + ?::bigint <= ?::bigint
            """;

    /** Statement deleting the rows older than an instant. */
    private static final String DELETE_OLDER_THAN = "DELETE FROM sms_cost_ledger WHERE sent_at < ?";

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    @Override
    public boolean tryRecord(final Instant sentAt, final String country, final long costMicros,
                             final SmsSpendCap windowCap, final SmsSpendCap dailyCap) {
        // the row mapper only drains the (void) result of the lock function
        jdbcClient.sql(LOCK).param(SPEND_LOCK_KEY).query((rs, rowNum) -> Boolean.TRUE).list();
        final var recorded = jdbcClient.sql(INSERT_WITHIN_CAPS)
                .params(toTimestamp(sentAt), country, costMicros,
                        toTimestamp(sentAt.minus(windowCap.window())), costMicros, windowCap.capMicros(),
                        toTimestamp(sentAt.minus(dailyCap.window())), costMicros, dailyCap.capMicros())
                .update() > 0;
        if (!recorded) {
            log.warn("An SMS was not sent: the spending cap has been reached");
        }
        return recorded;
    }

    @Override
    public int deleteOlderThan(final Instant before) {
        return jdbcClient.sql(DELETE_OLDER_THAN).param(toTimestamp(before)).update();
    }
}
