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

package com.irurueta.authserver.authorization.infrastructure.persistence.mfa;

import com.irurueta.authserver.authorization.domain.mfa.UserMfaSettingsRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link UserMfaSettingsRepository} over the {@code mfa_required} column of the {@code users} table.
 */
@Repository
@RequiredArgsConstructor
public class JdbcUserMfaSettingsRepository implements UserMfaSettingsRepository {

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    @Override
    public boolean isRequired(final UUID userId) {
        return jdbcClient.sql("SELECT mfa_required FROM users WHERE id = ?").param(userId).query(Boolean.class)
                .optional().orElse(false);
    }

    @Override
    public void setRequired(final UUID userId, final boolean required) {
        jdbcClient.sql("UPDATE users SET mfa_required = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
                .params(required, userId)
                .update();
    }
}
