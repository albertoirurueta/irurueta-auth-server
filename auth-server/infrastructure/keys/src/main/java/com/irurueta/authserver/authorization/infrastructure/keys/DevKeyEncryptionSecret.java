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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.HexFormat;
import lombok.extern.apachecommons.CommonsLog;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Provides the key-encryption inputs when the {@code dev} profile is active, so a developer does not have to
 * configure anything: a random passphrase and salt are generated once per machine, stored in a file under
 * {@code ~/.irurueta-auth-server/} that only the owner can read, and reused at every start, which keeps the signing
 * keys persisted in the development database decryptable across restarts. Values configured explicitly
 * ({@code authserver.keys.encryption.password} and {@code .salt}), as the end-to-end tests do, win over the file.
 *
 * <p>Why it lives in {@code src/main} although it only serves development: the end-to-end tests run the packaged
 * jar with the {@code dev} profile, and a class under {@code src/test} never reaches it (the same reason as for the
 * demo data initializer of the persistence adapter). It is inert everywhere else: without the {@code dev} profile
 * the bean is not created and the inputs must be configured. Nothing is ever written inside the repository.
 */
@CommonsLog
@Configuration(proxyBeanMethods = false)
@Profile("dev")
public class DevKeyEncryptionSecret {

    /** Directory, under the user's home, that holds the per-machine secret. */
    static final String DIRECTORY = ".irurueta-auth-server";

    /** Name of the file that holds the per-machine secret. */
    static final String FILE_NAME = "key-encryption";

    /** Source of the generated values. */
    private static final SecureRandom RANDOM = new SecureRandom();

    /** POSIX permissions of the secret file. */
    private static final String OWNER_ONLY = "rw-------";

    /** Number of random bytes of the generated passphrase. */
    private static final int PASSPHRASE_BYTES = 32;

    /** Number of random bytes of the generated salt. */
    private static final int SALT_BYTES = 16;

    /**
     * Creates the key-encryption inputs from configuration or, when that is missing, from the per-machine file.
     *
     * @param password configured passphrase, empty when not configured.
     * @param salt     configured hex-encoded salt, empty when not configured.
     * @return the inputs.
     */
    @Bean
    public KeyEncryptionProperties keyEncryptionProperties(
            @Value("${authserver.keys.encryption.password:}") final String password,
            @Value("${authserver.keys.encryption.salt:}") final String salt) {
        if (!password.isBlank() && !salt.isBlank()) {
            return new KeyEncryptionProperties(password, salt);
        }
        return load(Path.of(System.getProperty("user.home"), DIRECTORY));
    }

    /**
     * Reads the per-machine secret from a directory, creating it first when it does not exist yet.
     *
     * @param directory directory that holds the secret.
     * @return the inputs.
     * @throws UncheckedIOException if the secret cannot be read or created.
     */
    static KeyEncryptionProperties load(final Path directory) {
        final var file = directory.resolve(FILE_NAME);
        try {
            Files.createDirectories(directory);
            if (!Files.exists(file)) {
                create(file);
            }
            final var lines = Files.readAllLines(file);
            return new KeyEncryptionProperties(lines.get(0), lines.get(1));
        } catch (final IOException e) {
            throw new UncheckedIOException("Cannot read or create the development key-encryption secret", e);
        }
    }

    /**
     * Creates the secret file, readable by its owner only where the file system supports it.
     *
     * @param file the file to create.
     * @throws IOException if it cannot be written.
     */
    private static void create(final Path file) throws IOException {
        final var hex = HexFormat.of();
        final var passphraseBytes = new byte[PASSPHRASE_BYTES];
        final var saltBytes = new byte[SALT_BYTES];
        RANDOM.nextBytes(passphraseBytes);
        RANDOM.nextBytes(saltBytes);
        final var passphrase = hex.formatHex(passphraseBytes);
        final var salt = hex.formatHex(saltBytes);
        try {
            if (file.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                Files.createFile(file, PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString(OWNER_ONLY)));
            } else {
                Files.createFile(file);
            }
            Files.writeString(file, passphrase + "\n" + salt + "\n");
            log.warn("DEV ONLY: generated a key-encryption secret in " + file);
        } catch (final FileAlreadyExistsException e) {
            log.debug("The key-encryption secret was created concurrently", e);
        }
    }
}
