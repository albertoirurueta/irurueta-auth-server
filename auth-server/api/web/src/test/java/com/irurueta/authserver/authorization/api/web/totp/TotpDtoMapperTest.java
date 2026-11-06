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

package com.irurueta.authserver.authorization.api.web.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link TotpDtoMapper}.
 */
class TotpDtoMapperTest {

    /** Mapper under test. */
    private final TotpDtoMapper mapper = new TotpDtoMapper();

    /**
     * Verifies that both representations of the enrolment are copied.
     */
    @Test
    void toEnrollmentResponse_whenValuesAreGiven_copiesThem() {
        final var response = mapper.toEnrollmentResponse("otpauth://totp/x", "data:image/png;base64,AA");

        assertEquals("otpauth://totp/x", response.otpauthUri());
        assertEquals("data:image/png;base64,AA", response.qrCode());
    }

    /**
     * Verifies that every code of a new set is unused.
     */
    @Test
    void toRecoveryCodesResponse_whenCodesAreGiven_countsThemAsRemaining() {
        final var codes = List.of("A", "B", "C");

        final var response = mapper.toRecoveryCodesResponse(codes);

        assertEquals(codes, response.recoveryCodes());
        assertEquals(codes.size(), response.remaining());
    }
}
