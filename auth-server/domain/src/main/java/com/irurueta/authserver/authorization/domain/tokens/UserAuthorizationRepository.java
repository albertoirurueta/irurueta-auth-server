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

package com.irurueta.authserver.authorization.domain.tokens;

import java.time.Instant;

/**
 * Port that removes the stored authorizations (and so the tokens) of users.
 */
public interface UserAuthorizationRepository {

    /**
     * Deletes every authorization granted to a user.
     *
     * @param principalName name of the user the authorizations were granted to.
     * @return the number of deleted authorizations.
     */
    int deleteByPrincipalName(String principalName);

    /**
     * Deletes the authorizations whose every token has expired.
     *
     * @param now current instant.
     * @return the number of deleted authorizations.
     */
    int deleteExpired(Instant now);

    /**
     * Deletes the abandoned authorizations: those that never got any token (an authorization or consent request
     * the user never completed) and were created before an instant.
     *
     * @param createdBefore instant before which an abandoned authorization is deleted.
     * @return the number of deleted authorizations.
     */
    int deleteAbandoned(Instant createdBefore);
}
