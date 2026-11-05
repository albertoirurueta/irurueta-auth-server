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

package com.irurueta.authserver.authorization.domain.account;

import java.time.Instant;
import java.util.Optional;

/**
 * Port that stores single-use account tokens.
 */
public interface AccountTokenRepository {

    /**
     * Stores a new token.
     *
     * @param token the token to store.
     */
    void store(AccountToken token);

    /**
     * Consumes a token: finds an unused, unexpired token with the given hash and purpose and marks it as used, in
     * one atomic step, so that two concurrent calls can never both succeed.
     *
     * @param hashedToken hash of the token value.
     * @param purpose     purpose the token must have.
     * @param now         current instant, compared against the expiry.
     * @return the consumed token, or an empty optional when there is no such usable token.
     */
    Optional<AccountToken> consume(String hashedToken, String purpose, Instant now);

    /**
     * Deletes the tokens that expired before an instant.
     *
     * @param now current instant.
     * @return the number of deleted tokens.
     */
    int deleteExpired(Instant now);
}
