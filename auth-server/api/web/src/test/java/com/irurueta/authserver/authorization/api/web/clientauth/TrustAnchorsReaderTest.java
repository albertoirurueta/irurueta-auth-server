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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.testsupport.TestCertificates;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Unit tests of {@link TrustAnchorsReader}, with certificates generated at run time. */
class TrustAnchorsReaderTest {

    /** Certificates written by the test. */
    private static final int CERTIFICATES = 3;

    /** Reader under test. */
    private final TrustAnchorsReader reader = new TrustAnchorsReader();

    /** Directory of the test files. */
    @TempDir
    private Path directory;

    /**
     * No path gives no anchor.
     */
    @Test
    void read_whenNoPathIsGiven_returnsNoAnchor() {
        assertTrue(reader.read(List.of()).anchors().isEmpty());
    }

    /**
     * Every certificate of every file is an anchor, also when a file holds several.
     *
     * @throws IOException if a file cannot be written.
     */
    @Test
    void read_whenFilesHoldCertificates_returnsAnAnchorForEach() throws IOException {
        final var first = TestCertificates.generate("first-authority");
        final var second = TestCertificates.generate("second-authority");
        final var third = TestCertificates.generate("third-authority");
        final var single = directory.resolve("single.pem");
        final var bundle = directory.resolve("bundle.pem");
        Files.writeString(single, first.pem());
        Files.writeString(bundle, second.pem() + "\n" + third.pem());

        final var anchors = reader.read(List.of(single.toString(), bundle.toString())).anchors();

        assertEquals(CERTIFICATES, anchors.size());
        assertTrue(anchors.stream().anyMatch(anchor -> first.certificate().equals(anchor.getTrustedCert())));
    }

    /** A missing file is refused. */
    @Test
    void read_whenFileDoesNotExist_throwsIllegalArgumentException() {
        final var paths = List.of(directory.resolve("missing.pem").toString());

        assertThrows(IllegalArgumentException.class, () -> reader.read(paths));
    }

    /**
     * A file without a certificate is refused.
     *
     * @throws IOException if the file cannot be written.
     */
    @Test
    void read_whenFileHoldsNoCertificate_throwsIllegalArgumentException() throws IOException {
        final var file = directory.resolve("empty.pem");
        Files.writeString(file, "not a certificate");
        final var paths = List.of(file.toString());

        assertThrows(IllegalArgumentException.class, () -> reader.read(paths));
    }
}
