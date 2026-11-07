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

package com.irurueta.authserver.authorization.api.web.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link PasskeyViewMapper}.
 */
class PasskeyViewMapperTest {

    /** Creation instant. */
    private static final Instant CREATED = Instant.parse("2026-01-01T00:00:00Z");

    /** Mapper under test. */
    private final PasskeyViewMapper mapper = new PasskeyViewMapper();

    /**
     * Verifies that only what the page shows is copied, in order.
     */
    @Test
    void toViews_whenSeveralPasskeys_copiesWhatThePageShowsInOrder() {
        final var views = mapper.toViews(List.of(
                new Passkey("a", "handle", "First", CREATED, null, 1L, true, true),
                new Passkey("b", "handle", "Second", CREATED, CREATED.plusSeconds(1), 2L, false, false)));

        assertEquals(List.of(new PasskeyView("First", CREATED, null, true),
                new PasskeyView("Second", CREATED, CREATED.plusSeconds(1), false)), views);
    }
}
