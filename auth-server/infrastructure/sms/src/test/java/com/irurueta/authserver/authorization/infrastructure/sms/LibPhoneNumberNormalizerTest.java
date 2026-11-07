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

package com.irurueta.authserver.authorization.infrastructure.sms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link LibPhoneNumberNormalizer}, over the real libphonenumber. */
class LibPhoneNumberNormalizerTest {

    /** Test fixture. */
    private final LibPhoneNumberNormalizer normalizer = new LibPhoneNumberNormalizer(PhoneNumberUtil.getInstance());

    /** A national number is completed with the default region. */
    @Test
    void normalize_whenNationalNumber_usesDefaultRegion() {
        assertEquals(Optional.of(new PhoneNumber("+34612345678")), normalizer.normalize("612 34 56 78", "ES"));
    }

    /** An international number ignores the region. */
    @Test
    void normalize_whenInternationalNumber_returnsE164() {
        assertEquals(Optional.of(new PhoneNumber("+14155552671")), normalizer.normalize(" +1 (415) 555-2671 ", "ES"));
    }

    /** Garbage is refused. */
    @Test
    void normalize_whenGarbage_returnsEmpty() {
        assertTrue(normalizer.normalize("not a phone", "ES").isEmpty());
    }

    /** A blank input is refused. */
    @Test
    void normalize_whenBlank_returnsEmpty() {
        assertTrue(normalizer.normalize("   ", "ES").isEmpty());
    }

    /** A null input is refused. */
    @Test
    void normalize_whenNull_returnsEmpty() {
        assertTrue(normalizer.normalize(null, "ES").isEmpty());
    }

    /** A well-formed but invalid number is refused. */
    @Test
    void normalize_whenInvalidNumber_returnsEmpty() {
        assertTrue(normalizer.normalize("+34 123", "ES").isEmpty());
    }

    /** A national number without a usable region is refused instead of throwing. */
    @Test
    void normalize_whenNoRegionForNationalNumber_returnsEmpty() {
        assertTrue(normalizer.normalize("612345678", null).isEmpty());
    }
}
