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

import com.irurueta.authserver.authorization.domain.social.GeneratedPasswordRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link GeneratedPasswordRepository} over the {@code generated} column of {@code user_passwords}. It joins the
 * transaction of its caller.
 */
@Repository
@RequiredArgsConstructor
public class JdbcGeneratedPasswordRepository implements GeneratedPasswordRepository {

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    @Override
    public void markGenerated(final UUID userId) {
        jdbcClient.sql("UPDATE user_passwords SET generated = TRUE WHERE user_id = ?").param(userId).update();
    }

    @Override
    public boolean isGenerated(final UUID userId) {
        return jdbcClient.sql("SELECT count(*) FROM user_passwords WHERE user_id = ? AND generated").param(userId)
                .query(Long.class).single() > 0;
    }
}
