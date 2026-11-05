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

package com.irurueta.authserver.authorization.infrastructure.keys;

import com.irurueta.authserver.authorization.application.keys.SigningKeysRotatedEvent;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Drops every cached JWK set when the signing keys rotate, so the next token or JWKS request sees the new keys
 * without waiting for the cache to expire. It listens to an application event, so no web adapter needs to know
 * about this adapter.
 */
@Component
@RequiredArgsConstructor
public class JwkCacheRefreshListener {

    /** Every cached JWK set. */
    private final List<CachedJwkSet> caches;

    /**
     * Refreshes every cache.
     *
     * @param event the rotation that happened.
     */
    @EventListener
    public void onRotation(final SigningKeysRotatedEvent event) {
        caches.forEach(CachedJwkSet::refresh);
    }
}
