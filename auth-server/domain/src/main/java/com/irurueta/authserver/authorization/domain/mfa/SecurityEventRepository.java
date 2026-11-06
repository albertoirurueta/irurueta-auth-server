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
package com.irurueta.authserver.authorization.domain.mfa;

import java.util.List;
import java.util.UUID;

/**
 * Port that stores the audit trail of authentication events.
 */
public interface SecurityEventRepository {

    /**
     * Stores an event.
     *
     * @param event the event to store.
     */
    void store(SecurityEvent event);

    /**
     * Lists the most recent events of a user, newest first.
     *
     * @param userId identifier of the user.
     * @param limit  maximum number of events to return.
     * @return the events, possibly empty.
     */
    List<SecurityEvent> findRecentByUser(UUID userId, int limit);
}
