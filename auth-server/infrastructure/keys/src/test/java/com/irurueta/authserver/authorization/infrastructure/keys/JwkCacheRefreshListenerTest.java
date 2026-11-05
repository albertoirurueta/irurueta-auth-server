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

import static org.mockito.Mockito.verify;

import com.irurueta.authserver.authorization.application.keys.SigningKeysRotatedEvent;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link JwkCacheRefreshListener}.
 */
@ExtendWith(MockitoExtension.class)
class JwkCacheRefreshListenerTest {

    /** First cache. */
    @Mock
    private CachedJwkSet publishedCache;

    /** Second cache. */
    @Mock
    private CachedJwkSet signingCache;

    /** Subject under test. */
    private JwkCacheRefreshListener listener;

    /**
     * Creates the listener over the two mocked caches.
     */
    @BeforeEach
    void setUp() {
        listener = new JwkCacheRefreshListener(List.of(publishedCache, signingCache));
    }

    /**
     * A rotation refreshes every cache.
     */
    @Test
    void onRotation_whenKeysRotate_refreshesEveryCache() {
        listener.onRotation(new SigningKeysRotatedEvent(Instant.parse("2026-01-01T00:00:00Z")));

        verify(publishedCache).refresh();
        verify(signingCache).refresh();
    }
}
