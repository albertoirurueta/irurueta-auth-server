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
import java.time.Duration;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link SmsCostLedgerRepository} over the {@code sms_cost_ledger} table. It opens no transaction and takes no lock:
 * concurrent senders may each miss the other's row in the sum, which can overshoot a budget by at most the cost of the
 * messages in flight.
 */
@Repository
@RequiredArgsConstructor
public class JdbcSmsCostLedgerRepository implements SmsCostLedgerRepository {

    /**
     * Statement inserting a row and returning the spend of the window in one round trip. The rows of the window are
     * read by the main query, which does not see the row inserted by the same statement, so its cost is added.
     */
    private static final String RECORD_AND_SUM = """
            WITH inserted AS (
                INSERT INTO sms_cost_ledger (sent_at, country, cost_micros) VALUES (?, ?, ?)
                RETURNING cost_micros
            )
            SELECT ((SELECT COALESCE(SUM(cost_micros), 0) FROM sms_cost_ledger WHERE sent_at > ?)
                    + (SELECT cost_micros FROM inserted))::bigint
            """;

    /** Statement deleting the rows older than an instant. */
    private static final String DELETE_OLDER_THAN = "DELETE FROM sms_cost_ledger WHERE sent_at < ?";

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    @Override
    public long recordAndGetSpend(final Instant sentAt, final String country, final long costMicros,
                                  final Duration window) {
        return jdbcClient.sql(RECORD_AND_SUM)
                .params(toTimestamp(sentAt), country, costMicros, toTimestamp(sentAt.minus(window)))
                .query(Long.class)
                .single();
    }

    @Override
    public int deleteOlderThan(final Instant before) {
        return jdbcClient.sql(DELETE_OLDER_THAN).param(toTimestamp(before)).update();
    }
}
