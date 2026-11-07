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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;

/**
 * Provides the server certificate of the dedicated TLS port when the {@code dev} profile is active and none is
 * configured, so a developer does not have to create one: a self-signed certificate for {@code localhost} is generated
 * once per machine with the JDK's {@code keytool}, stored in a key store under {@code ~/.irurueta-auth-server/} that
 * only the owner can read (its password in a file next to it, as {@code DevKeyEncryptionSecret} keeps its secret) and
 * reused at every start. Nothing is ever written inside the repository.
 *
 * <p>Why it lives in {@code src/main} although it only serves development: the end-to-end tests run the packaged jar
 * with the {@code dev} profile, and a class under {@code src/test} never reaches it. It is inert everywhere else: the
 * bean exists only under the {@code dev} profile, and the port itself is off unless
 * {@code authserver.x509.port} is set. The clients' certificates are never validated by the connector (the
 * fingerprint binding is what identifies them), so the key store holds the server's certificate only.
 */
@Slf4j
public class DevX509KeyStore {

    /** Directory, under the user's home, that holds the per-machine files. */
    static final String DIRECTORY = ".irurueta-auth-server";

    /** Name of the key store file. */
    static final String KEY_STORE_FILE = "x509-tls.p12";

    /** Name of the file that holds the password of the key store. */
    static final String PASSWORD_FILE = "x509-tls.password";

    /** Type of the generated key store. */
    static final String KEY_STORE_TYPE = "PKCS12";

    /** POSIX permissions of the generated files. */
    private static final String OWNER_ONLY = "rw-------";

    /** Number of random bytes of the generated password. */
    private static final int PASSWORD_BYTES = 32;

    /** Validity of the generated certificate, in days. */
    private static final String VALIDITY_DAYS = "825";

    /** Longest time the generation may take. */
    private static final Duration GENERATION_TIMEOUT = Duration.ofMinutes(1);

    /** Source of the generated password. */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Reads the per-machine key store, generating it first when it does not exist yet, in the home directory of the
     * user.
     *
     * @return the key store.
     * @throws UncheckedIOException  if the files cannot be read or created.
     * @throws IllegalStateException if {@code keytool} fails.
     */
    public X509TlsKeyStore load() {
        return load(Path.of(System.getProperty("user.home"), DIRECTORY));
    }

    /**
     * Reads the key store of a directory, generating it first when it does not exist yet.
     *
     * @param directory directory that holds the key store and its password.
     * @return the key store.
     * @throws UncheckedIOException  if the files cannot be read or created.
     * @throws IllegalStateException if {@code keytool} fails.
     */
    X509TlsKeyStore load(final Path directory) {
        final var keyStore = directory.resolve(KEY_STORE_FILE);
        final var passwordFile = directory.resolve(PASSWORD_FILE);
        try {
            Files.createDirectories(directory);
            if (!Files.exists(keyStore) || !Files.exists(passwordFile)) {
                create(keyStore, passwordFile);
            }
            return new X509TlsKeyStore(keyStore, Files.readString(passwordFile).strip(), KEY_STORE_TYPE);
        } catch (final IOException e) {
            throw new UncheckedIOException("Cannot read or create the development X.509 key store", e);
        }
    }

    /**
     * Creates the password file and the key store, both readable by their owner only where the file system supports
     * it.
     *
     * @param keyStore     the key store to create.
     * @param passwordFile the file that holds its password.
     * @throws IOException if a file cannot be written or {@code keytool} cannot run.
     */
    private void create(final Path keyStore, final Path passwordFile) throws IOException {
        final var bytes = new byte[PASSWORD_BYTES];
        RANDOM.nextBytes(bytes);
        Files.deleteIfExists(keyStore);
        Files.deleteIfExists(passwordFile);
        try {
            createOwnerOnly(passwordFile);
            Files.writeString(passwordFile, HexFormat.of().formatHex(bytes) + "\n");
            runKeytool(keyStore, passwordFile);
            ownerOnly(keyStore);
            log.warn("DEV ONLY: generated a self-signed TLS key store for the X.509 port in {}", keyStore);
        } catch (final FileAlreadyExistsException e) {
            log.debug("The development X.509 key store was created concurrently", e);
        }
    }

    /**
     * Generates the key pair and its self-signed certificate.
     *
     * @param keyStore     the key store to create.
     * @param passwordFile the file that holds its password.
     * @throws IOException if {@code keytool} cannot run.
     */
    private void runKeytool(final Path keyStore, final Path passwordFile) throws IOException {
        final var keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        final var command = List.of(keytool, "-genkeypair", "-alias", "x509-tls", "-keyalg", "RSA", "-keysize", "3072",
                "-validity", VALIDITY_DAYS, "-dname", "CN=localhost", "-ext", "SAN=dns:localhost",
                "-storetype", KEY_STORE_TYPE, "-keystore", keyStore.toString(),
                "-storepass:file", passwordFile.toString());
        final var process = new ProcessBuilder(command).redirectErrorStream(true).start();
        try {
            final var output = new String(process.getInputStream().readAllBytes());
            if (!process.waitFor(GENERATION_TIMEOUT.toSeconds(), TimeUnit.SECONDS) || process.exitValue() != 0) {
                process.destroyForcibly();
                throw new IllegalStateException("keytool could not generate the X.509 key store: " + output);
            }
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new IllegalStateException("Interrupted while generating the X.509 key store", e);
        }
    }

    /**
     * Creates an empty file readable by its owner only, where the file system supports it.
     *
     * @param file the file to create.
     * @throws IOException if the file cannot be created.
     */
    private static void createOwnerOnly(final Path file) throws IOException {
        if (file.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(OWNER_ONLY)));
        } else {
            Files.createFile(file);
        }
    }

    /**
     * Restricts a file to its owner, where the file system supports it.
     *
     * @param file the file.
     * @throws IOException if the permissions cannot be changed.
     */
    private static void ownerOnly(final Path file) throws IOException {
        if (file.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString(OWNER_ONLY));
        }
    }
}
