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
package com.irurueta.authserver.authorization.infrastructure.persistence.social;

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.readInstant;

import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

/**
 * Maps a row of {@code federated_identities} to a {@link FederatedIdentity}.
 */
@Component
public class FederatedIdentityRowMapper implements RowMapper<FederatedIdentity> {

    /**
     * Maps the current row.
     *
     * @param rs     result set positioned on the row.
     * @param rowNum number of the row.
     * @return the identity; its e-mail address and last sign-in are {@code null} when none was stored.
     * @throws SQLException             if a column cannot be read.
     * @throws IllegalArgumentException if the stored provider is not a known one.
     */
    @Override
    public FederatedIdentity mapRow(final ResultSet rs, final int rowNum) throws SQLException {
        final var providerId = rs.getString("provider");
        final var provider = IdentityProvider.fromId(providerId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown identity provider " + providerId));
        return new FederatedIdentity(rs.getObject("id", UUID.class), rs.getObject("user_id", UUID.class), provider,
                rs.getString("subject"), rs.getString("email"), readInstant(rs, "linked_at"),
                readInstant(rs, "last_login_at"));
    }
}
