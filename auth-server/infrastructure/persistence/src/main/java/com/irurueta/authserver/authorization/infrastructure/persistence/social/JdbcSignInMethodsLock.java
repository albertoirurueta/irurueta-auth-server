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

import com.irurueta.authserver.authorization.domain.social.SignInMethodsLock;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link SignInMethodsLock} over a PostgreSQL transaction-level advisory lock on the account: it opens no transaction
 * and holds the lock until the caller's ends, so the removals of the sign-in methods of one account (unlinking an
 * identity, unbinding a certificate) run one after the other and each counts what the previous one left.
 */
@Repository
@RequiredArgsConstructor
public class JdbcSignInMethodsLock implements SignInMethodsLock {

    /** First key of the advisory locks of the accounts, which keeps them apart from every other advisory lock. */
    static final int SIGN_IN_METHODS_LOCK_NAMESPACE = 701;

    /** Statement taking the advisory lock of an account, released when the caller's transaction ends. */
    private static final String LOCK_ACCOUNT = "SELECT pg_advisory_xact_lock(?, hashtext(?))";

    /** JDBC client used to run the statement. */
    private final JdbcClient jdbcClient;

    @Override
    public void lock(final UUID userId) {
        jdbcClient.sql(LOCK_ACCOUNT).params(SIGN_IN_METHODS_LOCK_NAMESPACE, userId.toString())
                .query((rs, rowNum) -> Boolean.TRUE).list();
    }
}
