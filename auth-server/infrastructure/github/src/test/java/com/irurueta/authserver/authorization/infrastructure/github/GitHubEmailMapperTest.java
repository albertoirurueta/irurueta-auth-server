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
package com.irurueta.authserver.authorization.infrastructure.github;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.infrastructure.github.v1.generated.model.Email;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link GitHubEmailMapper}.
 */
class GitHubEmailMapperTest {

    /** The primary address of the tests. */
    private static final String MAIN = "main@example.org";

    /** Another address of the tests. */
    private static final String OTHER = "other@example.org";

    /** Mapper under test. */
    private final GitHubEmailMapper mapper = new GitHubEmailMapper();

    /**
     * Verifies that the address that is both primary and verified is chosen over a verified secondary one.
     */
    @Test
    void verifiedPrimary_whenPrimaryIsVerified_returnsIt() {
        final var emails = List.of(email(OTHER, false, true), email(MAIN, true, true));

        assertEquals(Optional.of(MAIN), mapper.verifiedPrimary(emails));
    }

    /**
     * Verifies that an unverified primary address is not returned, nor is a verified one that is not primary.
     */
    @Test
    void verifiedPrimary_whenPrimaryIsNotVerified_isEmpty() {
        final var emails = List.of(email(MAIN, true, false), email(OTHER, false, true));

        assertTrue(mapper.verifiedPrimary(emails).isEmpty());
    }

    /**
     * Verifies that missing flags, a blank address and a {@code null} entry do not count.
     */
    @Test
    void verifiedPrimary_whenFlagsOrAddressAreMissing_isEmpty() {
        final var emails = new ArrayList<Email>();
        emails.add(null);
        emails.add(new Email().email(MAIN));
        emails.add(email(" ", true, true));

        assertTrue(mapper.verifiedPrimary(emails).isEmpty());
    }

    /**
     * Verifies that an absent body is no address.
     */
    @Test
    void verifiedPrimary_whenListIsNull_isEmpty() {
        assertTrue(mapper.verifiedPrimary(null).isEmpty());
    }

    /**
     * Builds an address of the generated model.
     *
     * @param address  the address.
     * @param primary  whether it is primary.
     * @param verified whether it is verified.
     * @return the address.
     */
    private static Email email(final String address, final boolean primary, final boolean verified) {
        return new Email().email(address).primary(primary).verified(verified);
    }
}
