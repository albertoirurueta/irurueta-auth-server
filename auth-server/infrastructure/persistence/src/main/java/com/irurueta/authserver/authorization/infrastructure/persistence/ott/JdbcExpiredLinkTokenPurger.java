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

package com.irurueta.authserver.authorization.infrastructure.persistence.ott;

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.toTimestamp;

import com.irurueta.authserver.authorization.application.ott.ExpiredLinkTokenPurger;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link ExpiredLinkTokenPurger} over Spring Security's {@code one_time_tokens} table (magic links). It opens no
 * transaction: it is a single statement run in the caller's.
 */
@Repository
@RequiredArgsConstructor
public class JdbcExpiredLinkTokenPurger implements ExpiredLinkTokenPurger {

    /** Statement deleting the expired link tokens. */
    private static final String DELETE_EXPIRED = "DELETE FROM one_time_tokens WHERE expires_at <= ?";

    /** JDBC client used to run the statement. */
    private final JdbcClient jdbcClient;

    @Override
    public int deleteExpired(final Instant now) {
        return jdbcClient.sql(DELETE_EXPIRED).param(toTimestamp(now)).update();
    }
}
