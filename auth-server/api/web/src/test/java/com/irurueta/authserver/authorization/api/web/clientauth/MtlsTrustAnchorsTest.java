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
package com.irurueta.authserver.authorization.api.web.clientauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import java.security.cert.TrustAnchor;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link MtlsTrustAnchors}. */
class MtlsTrustAnchorsTest {

    /** The set is copied. */
    @Test
    void constructor_whenSetIsChangedAfterwards_isNotAffected() {
        final var original = new HashSet<TrustAnchor>();
        final var trustAnchors = new MtlsTrustAnchors(original);

        original.add(mock(TrustAnchor.class));

        assertEquals(Set.of(), trustAnchors.anchors());
    }
}
