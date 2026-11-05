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

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.toTimestamp;

import com.irurueta.authserver.authorization.domain.account.AccountToken;
import com.irurueta.authserver.authorization.domain.account.AccountTokenRepository;
import java.time.Instant;
import java.util.Optional;
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

    /** Query returning a token only when it is unused and not expired, without changing it. */
    private static final String FIND_USABLE_TOKEN = """
            SELECT id, user_id, purpose, hashed_token, expires_at, used_at FROM account_tokens
            WHERE hashed_token = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
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

    /** Maps a row to a token. */
    private final AccountTokenRowMapper accountTokenRowMapper;

    @Override
    public void store(final AccountToken token) {
        jdbcClient.sql(INSERT_TOKEN)
                .params(token.id(), token.userId(), token.purpose(), token.hashedToken(),
                        toTimestamp(token.expiresAt()), toTimestamp(token.usedAt()))
                .update();
    }

    @Override
    public Optional<AccountToken> findUsable(final String hashedToken, final String purpose, final Instant now) {
        return jdbcClient.sql(FIND_USABLE_TOKEN).params(hashedToken, purpose, toTimestamp(now))
                .query(accountTokenRowMapper)
                .optional();
    }

    @Override
    public Optional<AccountToken> consume(final String hashedToken, final String purpose, final Instant now) {
        final var timestamp = toTimestamp(now);
        return jdbcClient.sql(CONSUME_TOKEN).params(timestamp, hashedToken, purpose, timestamp)
                .query(accountTokenRowMapper)
                .optional();
    }

    @Override
    public int deleteExpired(final Instant now) {
        return jdbcClient.sql("DELETE FROM account_tokens WHERE expires_at <= ?").param(toTimestamp(now)).update();
    }
}
