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

package com.irurueta.authserver.authorization.infrastructure.persistence.account;

import com.irurueta.authserver.authorization.domain.account.AccountToken;
import com.irurueta.authserver.authorization.domain.account.AccountTokenRepository;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link AccountTokenRepository} over the {@code account_tokens} table.
 */
@Repository
@RequiredArgsConstructor
public class JdbcAccountTokenRepository implements AccountTokenRepository {

    /** Statement storing a token. */
    private static final String INSERT_TOKEN = """
            INSERT INTO account_tokens (id, user_id, purpose, hashed_token, expires_at, used_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """;

    // tag::account-token-consume[]
    /** Statement that marks a token as used and returns it, only when it is unused and not expired. */
    private static final String CONSUME_TOKEN = """
            UPDATE account_tokens SET used_at = ?
            WHERE hashed_token = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
            RETURNING id, user_id, purpose, hashed_token, expires_at, used_at
            """;
    // end::account-token-consume[]

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    @Override
    public void store(final AccountToken token) {
        jdbcClient.sql(INSERT_TOKEN)
                .params(token.id(), token.userId(), token.purpose(), token.hashedToken(),
                        toTimestamp(token.expiresAt()), toTimestamp(token.usedAt()))
                .update();
    }

    @Override
    public Optional<AccountToken> consume(final String hashedToken, final String purpose, final Instant now) {
        final var timestamp = toTimestamp(now);
        return jdbcClient.sql(CONSUME_TOKEN).params(timestamp, hashedToken, purpose, timestamp)
                .query((rs, rowNum) -> mapToken(rs))
                .optional();
    }

    @Override
    public int deleteExpired(final Instant now) {
        return jdbcClient.sql("DELETE FROM account_tokens WHERE expires_at <= ?").param(toTimestamp(now)).update();
    }

    /**
     * Converts an instant to the value bound to a {@code timestamp with time zone} column.
     *
     * @param instant the instant, or {@code null}.
     * @return the equivalent UTC date time, or {@code null}.
     */
    private static OffsetDateTime toTimestamp(final Instant instant) {
        return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
    }

    /**
     * Maps a row of {@code account_tokens} to a token.
     *
     * @param rs     result set positioned on the row.
     * @return the token.
     * @throws SQLException if a column cannot be read.
     */
    private static AccountToken mapToken(final ResultSet rs) throws SQLException {
        final var usedAt = rs.getObject("used_at", OffsetDateTime.class);
        return new AccountToken(rs.getObject("id", UUID.class), rs.getObject("user_id", UUID.class),
                rs.getString("purpose"), rs.getString("hashed_token"),
                rs.getObject("expires_at", OffsetDateTime.class).toInstant(),
                usedAt == null ? null : usedAt.toInstant());
    }
}
