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

package com.irurueta.authserver.authorization.domain.ott;

import java.time.Instant;

/**
 * Port that removes the expired magic-link tokens. The tokens are kept by Spring Security's one-time-token service,
 * a framework type the application layer must not use, so the persistence adapter implements this port over the
 * {@code one_time_tokens} table.
 */
public interface ExpiredLinkTokenPurger {

    /**
     * Deletes the tokens that expired at or before an instant.
     *
     * @param now the current instant.
     * @return the number of tokens deleted.
     */
    int deleteExpired(Instant now);
}
