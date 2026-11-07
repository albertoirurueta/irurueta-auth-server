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
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * A small public key infrastructure generated at run time for the tests of TLS client authentication: a certificate
 * authority, and server and client certificates it signs, each kept in a PKCS#12 key store inside one temporary
 * directory that {@link #close()} deletes. It drives {@code keytool} (see {@link Keytool}); nothing is ever kept in
 * the repository.
 */
public final class TestPki implements AutoCloseable {

    /** Alias of the authority's key. */
    private static final String CA_ALIAS = "ca";

    /** Alias of the key of an issued entity. */
    private static final String ENTITY_ALIAS = "entity";

    /** Type of the key stores. */
    private static final String KEY_STORE_TYPE = "PKCS12";

    /** Number of random bytes of the password of the key stores. */
    private static final int PASSWORD_BYTES = 16;

    /** Days the issued certificates are valid. */
    private static final String VALIDITY_DAYS = "2";

    /** The {@code keytool} option that names a key store. */
    private static final String KEYSTORE = "-keystore";

    /** The {@code keytool} option that names the file with a key store password. */
    private static final String STORE_PASSWORD_FILE = "-storepass:file";

    /** The {@code keytool} option that names the alias of an entry. */
    private static final String ALIAS = "-alias";

    /** The {@code keytool} option that names the input file. */
    private static final String INPUT = "-file";

    /** Source of the password. */
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Temporary directory that holds every file. */
    private final Path directory;

    /** Password of every key store. */
    private final String password;

    /** File that holds {@link #password}. */
    private final Path passwordFile;

    /** Key store of the authority. */
    private final Path authorityKeyStore;

    /** Certificate of the authority. */
    private final X509Certificate authority;

    /** Path of the authority's certificate in PEM. */
    private final Path authorityPem;

    /** Number of entities issued, to name their files. */
    private int issued;

    /**
     * Describes an infrastructure whose files already exist.
     *
     * @param directory temporary directory that holds every file.
     * @param password  password of every key store.
     * @param authority certificate of the authority.
     */
    private TestPki(final Path directory, final String password, final X509Certificate authority) {
        this.directory = directory;
        this.password = password;
        passwordFile = directory.resolve("password");
        authorityKeyStore = directory.resolve("ca.p12");
        authorityPem = directory.resolve("ca.pem");
        this.authority = authority;
    }

    /**
     * Creates the infrastructure with a new certificate authority.
     *
     * @param authorityName common name of the authority.
     * @return the infrastructure; the caller closes it.
     */
    public static TestPki create(final String authorityName) {
        final var bytes = new byte[PASSWORD_BYTES];
        RANDOM.nextBytes(bytes);
        final var password = HexFormat.of().formatHex(bytes);
        Path directory = null;
        try {
            directory = Files.createTempDirectory("test-pki");
            Files.writeString(directory.resolve("password"), password);
            final var keyStore = directory.resolve("ca.p12");
            final var passwordFile = directory.resolve("password").toString();
            Keytool.run(List.of("-genkeypair", ALIAS, CA_ALIAS, "-keyalg", "EC", "-groupname", "secp256r1",
                    "-validity", VALIDITY_DAYS, "-dname", "CN=" + authorityName, "-ext", "bc:c",
                    "-storetype", KEY_STORE_TYPE, KEYSTORE, keyStore.toString(), STORE_PASSWORD_FILE, passwordFile));
            final var pem = directory.resolve("ca.pem");
            Keytool.run(List.of("-exportcert", ALIAS, CA_ALIAS, "-rfc", KEYSTORE, keyStore.toString(),
                    STORE_PASSWORD_FILE, passwordFile, "-file", pem.toString()));
            return new TestPki(directory, password, readCertificate(pem));
        } catch (final IOException | GeneralSecurityException e) {
            Keytool.delete(directory);
            throw new IllegalStateException("Cannot create the test infrastructure", e);
        }
    }

    /**
     * Issues the certificate of a TLS server, valid for {@code localhost} and the loopback address.
     *
     * @param commonName common name of the subject.
     * @return the server's key store and certificate.
     */
    public Identity issueServer(final String commonName) {
        return issue(commonName, List.of("-ext", "san=dns:localhost,ip:127.0.0.1", "-ext", "eku=serverAuth"));
    }

    /**
     * Issues the certificate of a client, signed by the authority.
     *
     * @param commonName common name of the subject.
     * @return the client's key store and certificate.
     */
    public Identity issueClient(final String commonName) {
        return issue(commonName, List.of("-ext", "eku=clientAuth"));
    }

    /**
     * Gives the TLS context of a client that presents a certificate and trusts the authority.
     *
     * @param client the client's identity, {@code null} for a client with no certificate.
     * @return the context.
     */
    public SSLContext clientContext(final Identity client) {
        try {
            final var trust = KeyStore.getInstance(KEY_STORE_TYPE);
            trust.load(null, null);
            trust.setCertificateEntry(CA_ALIAS, authority);
            final var trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trust);
            final var context = SSLContext.getInstance("TLS");
            if (client == null) {
                context.init(null, trustManagers.getTrustManagers(), null);
            } else {
                final var keys = KeyStore.getInstance(KEY_STORE_TYPE);
                try (InputStream in = Files.newInputStream(client.keyStore())) {
                    keys.load(in, client.password().toCharArray());
                }
                final var keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagers.init(keys, client.password().toCharArray());
                context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
            }
            return context;
        } catch (final IOException e) {
            throw new UncheckedIOException("Cannot read the test key store", e);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("Cannot build the test TLS context", e);
        }
    }

    /**
     * Gives the identity of a client with a self-signed certificate that expired days ago.
     *
     * @param commonName common name of the subject.
     * @return the client's key store and certificate.
     */
    public Identity issueExpiredClient(final String commonName) {
        final var name = nextName();
        final var keyStore = directory.resolve(name + ".p12");
        try {
            Keytool.run(List.of("-genkeypair", ALIAS, ENTITY_ALIAS, "-keyalg", "EC", "-groupname", "secp256r1",
                    "-startdate", "-5d", "-validity", VALIDITY_DAYS, "-dname", "CN=" + commonName,
                    "-storetype", KEY_STORE_TYPE, KEYSTORE, keyStore.toString(),
                    STORE_PASSWORD_FILE, passwordFile.toString()));
            return identityOf(keyStore);
        } catch (final IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Cannot issue the expired test certificate", e);
        }
    }

    @Override
    public void close() {
        Keytool.delete(directory);
    }

    /**
     * Issues an entity signed by the authority.
     *
     * @param commonName common name of the subject.
     * @param extensions the {@code keytool} extension options the certificate gets.
     * @return the entity's key store and certificate.
     */
    private Identity issue(final String commonName, final List<String> extensions) {
        final var name = nextName();
        final var keyStore = directory.resolve(name + ".p12");
        final var request = directory.resolve(name + ".csr");
        final var reply = directory.resolve(name + ".pem");
        try {
            Keytool.run(List.of("-genkeypair", ALIAS, ENTITY_ALIAS, "-keyalg", "EC", "-groupname", "secp256r1",
                    "-validity", VALIDITY_DAYS, "-dname", "CN=" + commonName, "-storetype", KEY_STORE_TYPE,
                    KEYSTORE, keyStore.toString(), STORE_PASSWORD_FILE, passwordFile.toString()));
            Keytool.run(List.of("-certreq", ALIAS, ENTITY_ALIAS, KEYSTORE, keyStore.toString(),
                    STORE_PASSWORD_FILE, passwordFile.toString(), "-file", request.toString()));
            return identityOf(sign(keyStore, request, reply, extensions));
        } catch (final IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Cannot issue the test certificate", e);
        }
    }

    /**
     * Has the authority sign a request and installs the answer in the entity's key store.
     *
     * @param keyStore   key store of the entity.
     * @param request    certificate request of the entity.
     * @param reply      file the signed certificate is written to.
     * @param extensions the {@code keytool} extension options the certificate gets.
     * @return the entity's key store.
     * @throws IOException if {@code keytool} fails.
     */
    private Path sign(final Path keyStore, final Path request, final Path reply, final List<String> extensions)
            throws IOException {
        final var gencert = new ArrayList<>(List.of("-gencert", ALIAS, CA_ALIAS, "-rfc", "-validity", VALIDITY_DAYS,
                KEYSTORE, authorityKeyStore.toString(), STORE_PASSWORD_FILE, passwordFile.toString(),
                "-infile", request.toString(), "-outfile", reply.toString()));
        gencert.addAll(extensions);
        Keytool.run(gencert);
        Keytool.run(List.of("-importcert", ALIAS, CA_ALIAS, INPUT, authorityPem.toString(), KEYSTORE,
                keyStore.toString(), STORE_PASSWORD_FILE, passwordFile.toString(), "-noprompt"));
        Keytool.run(List.of("-importcert", ALIAS, ENTITY_ALIAS, INPUT, reply.toString(), KEYSTORE,
                keyStore.toString(), STORE_PASSWORD_FILE, passwordFile.toString()));
        return keyStore;
    }

    /**
     * Reads an identity from its key store.
     *
     * @param keyStore the key store.
     * @return the identity.
     * @throws IOException              if the key store cannot be read.
     * @throws GeneralSecurityException if the key store cannot be loaded.
     */
    private Identity identityOf(final Path keyStore) throws IOException, GeneralSecurityException {
        final var store = KeyStore.getInstance(KEY_STORE_TYPE);
        try (InputStream in = Files.newInputStream(keyStore)) {
            store.load(in, password.toCharArray());
        }
        return new Identity(keyStore, password,
                TestCertificates.of((X509Certificate) store.getCertificate(ENTITY_ALIAS)));
    }

    /**
     * Names the files of the next entity.
     *
     * @return the name.
     */
    private String nextName() {
        issued++;
        return "entity-" + issued;
    }

    /**
     * Reads a PEM certificate.
     *
     * @param pem the file.
     * @return the certificate.
     * @throws IOException              if the file cannot be read.
     * @throws GeneralSecurityException if it is not a certificate.
     */
    private static X509Certificate readCertificate(final Path pem) throws IOException, GeneralSecurityException {
        try (InputStream in = Files.newInputStream(pem)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    /**
     * An identity of the infrastructure.
     *
     * @param keyStore    PKCS#12 key store with the private key and the certificate chain.
     * @param password    password of the key store.
     * @param certificate the certificate of the identity, with its PEM text and fingerprint.
     */
    public record Identity(Path keyStore, String password, TestCertificates.GeneratedCertificate certificate) {

        @Override
        public String toString() {
            return "Identity[keyStore=" + keyStore + "]";
        }
    }
}
