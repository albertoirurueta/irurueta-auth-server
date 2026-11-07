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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests of {@link DevX509KeyStore}, which runs the {@code keytool} of the JDK that runs the tests.
 */
class DevX509KeyStoreTest {

    /** Generator under test. */
    private final DevX509KeyStore generator = new DevX509KeyStore();

    /**
     * Verifies that the key store is generated once, readable by its owner only, and reused afterwards.
     *
     * @param directory a temporary directory.
     * @throws IOException              if a file cannot be read.
     * @throws GeneralSecurityException if the key store cannot be opened.
     */
    @Test
    void load_whenNothingExists_generatesTheKeyStoreOnceAndReusesIt(@TempDir final Path directory)
            throws IOException, GeneralSecurityException {
        final var first = generator.load(directory);
        final var modified = Files.getLastModifiedTime(first.location());
        final var second = generator.load(directory);

        assertEquals(first, second);
        assertEquals(first.password(), second.password());
        assertEquals(modified, Files.getLastModifiedTime(second.location()));
        assertEquals("PKCS12", first.type());
        final var keyStore = KeyStore.getInstance(first.type());
        try (var in = Files.newInputStream(first.location())) {
            keyStore.load(in, first.password().toCharArray());
        }
        assertTrue(keyStore.containsAlias("x509-tls"));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(first.location())));
        assertEquals("rw-------", PosixFilePermissions.toString(
                Files.getPosixFilePermissions(directory.resolve(DevX509KeyStore.PASSWORD_FILE))));
    }

    /**
     * Verifies that a key store whose password is lost is generated again, with a new password.
     *
     * @param directory a temporary directory.
     * @throws IOException if a file cannot be read.
     */
    @Test
    void load_whenThePasswordFileIsMissing_generatesANewKeyStore(@TempDir final Path directory) throws IOException {
        final var first = generator.load(directory);
        Files.delete(directory.resolve(DevX509KeyStore.PASSWORD_FILE));

        final var second = generator.load(directory);

        assertNotEquals(first.password(), second.password());
    }

    /**
     * Verifies that the key store of the user is kept in the {@code .irurueta-auth-server} directory of the home.
     *
     * @param home a temporary directory standing for the home of the user.
     */
    @Test
    void load_whenNoDirectoryIsGiven_usesTheHomeOfTheUser(@TempDir final Path home) {
        final var previous = System.getProperty("user.home");
        System.setProperty("user.home", home.toString());
        try {
            final var keyStore = generator.load();

            assertEquals(home.resolve(DevX509KeyStore.DIRECTORY).resolve(DevX509KeyStore.KEY_STORE_FILE),
                    keyStore.location());
        } finally {
            System.setProperty("user.home", previous);
        }
    }
}
