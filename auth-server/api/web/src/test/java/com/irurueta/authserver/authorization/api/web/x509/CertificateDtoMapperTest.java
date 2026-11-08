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
package com.irurueta.authserver.authorization.api.web.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.authorization.api.web.v1.generated.model.Certificate;
import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link CertificateDtoMapper}.
 */
class CertificateDtoMapperTest {

    /** Fingerprint used by the tests. */
    private static final String FINGERPRINT = "d".repeat(CertificateBinding.FINGERPRINT_LENGTH);

    /** Instant the certificate was bound. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Mapper under test. */
    private final CertificateDtoMapper mapper = new CertificateDtoMapper();

    /**
     * Verifies that every public field is mapped and the account is left out.
     */
    @Test
    void toResponse_whenCalled_mapsThePublicFields() {
        final var binding = new CertificateBinding(UUID.randomUUID(), UUID.randomUUID(), FINGERPRINT, "CN=alice",
                CREATED_AT);

        assertEquals(new Certificate(binding.id(), FINGERPRINT, "CN=alice", CREATED_AT), mapper.toResponse(binding));
    }

    /**
     * Verifies that several bindings keep their order.
     */
    @Test
    void toResponses_whenCalled_keepsTheOrder() {
        final var first = new CertificateBinding(UUID.randomUUID(), UUID.randomUUID(), FINGERPRINT, "CN=a",
                CREATED_AT);
        final var second = new CertificateBinding(UUID.randomUUID(), UUID.randomUUID(),
                "e".repeat(CertificateBinding.FINGERPRINT_LENGTH), "CN=b", CREATED_AT);

        final var responses = mapper.toResponses(List.of(first, second));

        assertEquals(List.of(first.id(), second.id()), responses.stream().map(Certificate::id).toList());
    }
}
