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
package com.irurueta.authserver.testsupport;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Generates self-signed client certificates at run time for the tests of the sign-in with a client certificate, so no
 * certificate, key or key store is ever kept in the repository. It drives the {@code keytool} of the JDK that runs the
 * tests: the JDK has no public API to issue a certificate, and a key store file only exists in a temporary directory
 * for the time it takes to read the certificate back.
 */
public final class TestCertificates {

    /** Alias of the generated key. */
    private static final String ALIAS = "test";

    /** Type of the key store the certificate is read from. */
    private static final String KEY_STORE_TYPE = "PKCS12";

    /** Start of the validity of an expired certificate: five days ago, so that its two days are long gone. */
    private static final String EXPIRED_START = "-5d";

    /** Number of random bytes of the password of the temporary key store. */
    private static final int PASSWORD_BYTES = 16;

    /** Characters of a line of a PEM certificate. */
    private static final int PEM_LINE_LENGTH = 64;

    /** Source of the password of the temporary key store. */
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Not instantiable. */
    private TestCertificates() {
    }

    /**
     * Generates a self-signed certificate.
     *
     * @param commonName common name of the subject.
     * @return the certificate, with its PEM text and its SHA-256 fingerprint.
     */
    public static GeneratedCertificate generate(final String commonName) {
        return generate(commonName, List.of());
    }

    /**
     * Generates a self-signed certificate that expired days ago.
     *
     * @param commonName common name of the subject.
     * @return the certificate, with its PEM text and its SHA-256 fingerprint.
     */
    public static GeneratedCertificate generateExpired(final String commonName) {
        return generate(commonName, List.of("-startdate", EXPIRED_START));
    }

    /**
     * Generates a self-signed certificate.
     *
     * @param commonName common name of the subject.
     * @param extra      additional {@code keytool} arguments.
     * @return the certificate, with its PEM text and its SHA-256 fingerprint.
     */
    private static GeneratedCertificate generate(final String commonName, final List<String> extra) {
        final var bytes = new byte[PASSWORD_BYTES];
        RANDOM.nextBytes(bytes);
        final var password = HexFormat.of().formatHex(bytes);
        Path directory = null;
        try {
            directory = Files.createTempDirectory("test-certificate");
            final var passwordFile = Files.writeString(directory.resolve("password"), password);
            final var keyStoreFile = directory.resolve("store.p12");
            final var command = new ArrayList<>(List.of("-genkeypair",
                    "-alias", ALIAS, "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "2",
                    "-dname", "CN=" + commonName, "-storetype", KEY_STORE_TYPE,
                    "-keystore", keyStoreFile.toString(), "-storepass:file", passwordFile.toString()));
            command.addAll(extra);
            Keytool.run(command);
            final var keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            try (var in = Files.newInputStream(keyStoreFile)) {
                keyStore.load(in, password.toCharArray());
            }
            return of((X509Certificate) keyStore.getCertificate(ALIAS));
        } catch (final IOException e) {
            throw new UncheckedIOException("Cannot generate a test certificate", e);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("Cannot read the generated test certificate", e);
        } finally {
            Keytool.delete(directory);
        }
    }

    /**
     * Describes a certificate.
     *
     * @param certificate the certificate.
     * @return the certificate with its PEM text and its SHA-256 fingerprint.
     */
    public static GeneratedCertificate of(final X509Certificate certificate) {
        try {
            final var encoded = certificate.getEncoded();
            final var pem = "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(PEM_LINE_LENGTH, "\n".getBytes(StandardCharsets.US_ASCII))
                            .encodeToString(encoded)
                    + "\n-----END CERTIFICATE-----\n";
            final var fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(encoded));
            return new GeneratedCertificate(certificate, pem, fingerprint);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("Cannot describe the test certificate", e);
        }
    }

    /**
     * A generated certificate.
     *
     * @param certificate       the certificate.
     * @param pem               its PEM text.
     * @param fingerprintSha256 its SHA-256 fingerprint, as 64 lower case hexadecimal digits.
     */
    public record GeneratedCertificate(X509Certificate certificate, String pem, String fingerprintSha256) {
    }
}
