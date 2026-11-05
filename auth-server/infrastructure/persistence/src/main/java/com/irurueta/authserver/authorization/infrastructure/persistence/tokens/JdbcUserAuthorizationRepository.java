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

package com.irurueta.authserver.authorization.infrastructure.persistence.tokens;

import com.irurueta.authserver.authorization.domain.tokens.UserAuthorizationRepository;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZoneOffset;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link UserAuthorizationRepository} over the {@code oauth2_authorization} table.
 */
@Repository
@RequiredArgsConstructor
public class JdbcUserAuthorizationRepository implements UserAuthorizationRepository {

    /**
     * Statement deleting the authorizations whose every token has expired. {@code GREATEST} ignores the tokens an
     * authorization does not have, and is null for an authorization without any expiry, which is kept here and
     * removed by {@link #deleteAbandoned(Instant)} once it is old enough.
     */
    private static final String DELETE_EXPIRED = """
            DELETE FROM oauth2_authorization
            WHERE GREATEST(authorization_code_expires_at, access_token_expires_at, oidc_id_token_expires_at,
                           refresh_token_expires_at, user_code_expires_at, device_code_expires_at) < ?
            """;

    /**
     * Statement deleting the abandoned authorizations: no token was ever issued for them, so every expiry column is
     * null, and they were created before the given instant.
     */
    private static final String DELETE_ABANDONED = """
            DELETE FROM oauth2_authorization
            WHERE authorization_code_expires_at IS NULL AND access_token_expires_at IS NULL
              AND oidc_id_token_expires_at IS NULL AND refresh_token_expires_at IS NULL
              AND user_code_expires_at IS NULL AND device_code_expires_at IS NULL
              AND created_at < ?
            """;

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    @Override
    public int deleteByPrincipalName(final String principalName) {
        return jdbcClient.sql("DELETE FROM oauth2_authorization WHERE principal_name = ?").param(principalName)
                .update();
    }

    @Override
    public int deleteExpired(final Instant now) {
        // the SAS columns are "timestamp without time zone", written by the framework in the JVM's default zone
        return jdbcClient.sql(DELETE_EXPIRED).param(Timestamp.from(now)).update();
    }

    @Override
    public int deleteAbandoned(final Instant createdBefore) {
        // created_at is "timestamp with time zone" (V240), so the instant is bound with an explicit offset
        return jdbcClient.sql(DELETE_ABANDONED).param(createdBefore.atOffset(ZoneOffset.UTC)).update();
    }
}
