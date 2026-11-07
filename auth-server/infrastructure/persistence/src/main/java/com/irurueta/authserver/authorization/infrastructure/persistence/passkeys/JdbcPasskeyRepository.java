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

package com.irurueta.authserver.authorization.infrastructure.persistence.passkeys;

import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link PasskeyRepository} over the {@code user_credentials} and {@code user_entities} tables that Spring Security's
 * WebAuthn repositories own. It only reads them and renames or deletes a credential; registering one and updating its
 * signature counter stay with the framework.
 */
@Repository
@RequiredArgsConstructor
public class JdbcPasskeyRepository implements PasskeyRepository {

    /** Columns of a credential, in the order the row mapper does not depend on. */
    private static final String COLUMNS = """
            credential_id, user_entity_user_id, label, created, last_used, signature_count, backup_eligible,
            backup_state""";

    /** Query returning the user handle of an account. */
    private static final String FIND_USER_ID_BY_USERNAME = """
            SELECT id FROM user_entities WHERE name = ? ORDER BY id LIMIT 1
            """;

    /** Query returning the credentials of a user. */
    private static final String FIND_BY_USER_ID = "SELECT " + COLUMNS + """
             FROM user_credentials WHERE user_entity_user_id = ? ORDER BY created, credential_id
            """;

    /** Query returning one credential of a user. */
    private static final String FIND_BY_ID_AND_USER_ID = "SELECT " + COLUMNS + """
             FROM user_credentials WHERE credential_id = ? AND user_entity_user_id = ?
            """;

    /** Statement renaming a credential of a user. */
    private static final String RENAME = """
            UPDATE user_credentials SET label = ? WHERE credential_id = ? AND user_entity_user_id = ?
            """;

    /** Statement deleting a credential of a user. */
    private static final String DELETE = """
            DELETE FROM user_credentials WHERE credential_id = ? AND user_entity_user_id = ?
            """;

    /** Query counting the credentials of a user. */
    private static final String COUNT_BY_USER_ID = """
            SELECT count(*) FROM user_credentials WHERE user_entity_user_id = ?
            """;

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Maps a row to a passkey. */
    private final PasskeyRowMapper passkeyRowMapper;

    @Override
    public Optional<String> findUserIdByUsername(final String username) {
        return jdbcClient.sql(FIND_USER_ID_BY_USERNAME).param(username).query(String.class).optional();
    }

    @Override
    public List<Passkey> findByUserId(final String userId) {
        return jdbcClient.sql(FIND_BY_USER_ID).param(userId).query(passkeyRowMapper).list();
    }

    @Override
    public Optional<Passkey> findByIdAndUserId(final String id, final String userId) {
        return jdbcClient.sql(FIND_BY_ID_AND_USER_ID).params(id, userId).query(passkeyRowMapper).optional();
    }

    @Override
    public boolean rename(final String id, final String userId, final String label) {
        return jdbcClient.sql(RENAME).params(label, id, userId).update() > 0;
    }

    @Override
    public boolean delete(final String id, final String userId) {
        return jdbcClient.sql(DELETE).params(id, userId).update() > 0;
    }

    @Override
    public long countByUserId(final String userId) {
        return jdbcClient.sql(COUNT_BY_USER_ID).param(userId).query(Long.class).single();
    }
}
