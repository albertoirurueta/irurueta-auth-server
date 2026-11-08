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
package com.irurueta.authserver.authorization.api.web.social;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

/**
 * The marker a signed-in user leaves in the session when asking to link an identity of an external provider: the next
 * sign-in with that provider, before the marker expires, links the identity to this account instead of signing
 * anybody in. It is kept in the session, so it is serializable.
 *
 * @param providerId registration id of the provider.
 * @param userId     identifier of the signed-in account.
 * @param username   name of the signed-in account.
 * @param expiresAt  instant after which the marker is ignored.
 */
public record PendingIdentityLink(String providerId, UUID userId, String username, Instant expiresAt)
        implements Serializable {

    /** Serialization version. */
    @Serial
    private static final long serialVersionUID = 1L;
}
