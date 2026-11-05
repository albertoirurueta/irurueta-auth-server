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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests of {@link DevKeyEncryptionSecret}.
 */
class DevKeyEncryptionSecretTest {

    /** Temporary directory standing in for the user's home. */
    @TempDir
    private Path home;

    /**
     * Verifies that the first load creates the file and the second reuses it.
     *
     * @throws IOException if the file cannot be read.
     */
    @Test
    void load_whenCalledTwice_createsOnceAndReuses() throws IOException {
        final var directory = home.resolve(DevKeyEncryptionSecret.DIRECTORY);

        final var first = DevKeyEncryptionSecret.load(directory);
        final var second = DevKeyEncryptionSecret.load(directory);

        assertEquals(first, second);
        assertTrue(Files.exists(directory.resolve(DevKeyEncryptionSecret.FILE_NAME)));
        assertNotEquals(first.password(), first.salt());
        assertEquals(2, Files.readAllLines(directory.resolve(DevKeyEncryptionSecret.FILE_NAME)).size());
    }

    /**
     * Verifies that two machines get different secrets.
     */
    @Test
    void load_whenDirectoriesDiffer_generatesDifferentSecrets() {
        final var first = DevKeyEncryptionSecret.load(home.resolve("one"));
        final var second = DevKeyEncryptionSecret.load(home.resolve("two"));

        assertNotEquals(first, second);
    }

    /**
     * Verifies that the generated inputs can drive the cipher.
     */
    @Test
    void load_whenGenerated_workWithTheCipher() {
        final var cipher = new AesGcmKeyCipher(DevKeyEncryptionSecret.load(home));
        final var plain = UUID.randomUUID().toString();

        assertEquals(plain, cipher.decrypt(cipher.encrypt(plain)));
    }

    /**
     * Verifies that explicitly configured values are used and no file is touched.
     */
    @Test
    void keyEncryptionProperties_whenValuesAreConfigured_usesThem() {
        final var first = UUID.randomUUID().toString();
        final var second = UUID.randomUUID().toString();

        final var properties = new DevKeyEncryptionSecret().keyEncryptionProperties(first, second);

        assertEquals(new KeyEncryptionProperties(first, second), properties);
    }

    /**
     * Verifies that a path that cannot be a directory is reported.
     *
     * @throws IOException if the blocking file cannot be created.
     */
    @Test
    void load_whenDirectoryCannotBeCreated_throwsUncheckedIOException() throws IOException {
        final var blocker = Files.createFile(home.resolve("blocker"));

        assertThrows(UncheckedIOException.class, () -> DevKeyEncryptionSecret.load(blocker.resolve("sub")));
    }
}
