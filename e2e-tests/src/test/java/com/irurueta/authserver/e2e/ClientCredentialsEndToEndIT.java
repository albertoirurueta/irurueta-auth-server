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
package com.irurueta.authserver.e2e;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.testsupport.TestCertificates;
import com.irurueta.authserver.testsupport.TestPki;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * End-to-end test of the non-interactive flow with the packaged applications: the {@code service-client} jar gets a
 * token with the {@code client_credentials} grant from the {@code auth-server} and reads {@code GET /api/documents}
 * from the {@code resource-server}, once per client authentication method ({@code client_secret_basic},
 * {@code private_key_jwt}, {@code tls_client_auth}, {@code self_signed_tls_client_auth}) and with DPoP. Every key and
 * certificate is generated at run time. A token that is bound to a certificate or to a DPoP key, printed by the run and
 * replayed without that proof of possession, must be refused by the resource server.
 */
class ClientCredentialsEndToEndIT {

    /** Redirect URI of the seeded {@code bff} client; the server only needs one to seed it. */
    private static final String BFF_REDIRECT_URI = "http://127.0.0.1:8099/callback";

    /** The grant of the clients under test. */
    private static final String CLIENT_CREDENTIALS = "client_credentials";

    /** HTTP status of a successful response. */
    private static final int HTTP_OK = 200;

    /** HTTP status of an unauthorized response. */
    private static final int HTTP_UNAUTHORIZED = 401;

    /** Name of the SSL bundle of the service client. */
    private static final String BUNDLE = "mtls";

    /** Key size of the generated RSA key of {@code private_key_jwt}. */
    private static final int RSA_KEY_BITS = 2048;

    /** Alias of the private key of a {@link TestPki} identity. */
    private static final String ENTITY_ALIAS = "entity";

    /** Alias of the key of the authority of a {@link TestPki}, used as a self-signed certificate. */
    private static final String AUTHORITY_ALIAS = "ca";

    /** Name of the claim that holds the confirmation (proof of possession) of a token. */
    private static final String CNF = "cnf";

    /** The test infrastructure that issues the server and client certificates. */
    private static final TestPki PKI = TestPki.create("e2e-authority-" + UUID.randomUUID());

    /** The test infrastructure whose authority certificate plays the self-signed client certificate. */
    private static final TestPki SELF_SIGNED_PKI = TestPki.create("e2e-self-signed-" + UUID.randomUUID());

    /** Server certificate of the TLS port of the authorization server and of the TLS resource server. */
    private static final TestPki.Identity SERVER = PKI.issueServer("localhost");

    /** Client certificate issued by the trusted authority. */
    private static final TestPki.Identity TRUSTED_CLIENT = PKI.issueClient("e2e-mtls-client");

    /** The packaged authorization server and its database. */
    private static RunningAuthServer authServer;

    /** Registers the clients. */
    private static ClientAdminApi admin;

    /** Resource server over plain HTTP. */
    private static RunningResourceServer plainResourceServer;

    /** Resource server over TLS that requests (does not require) a client certificate. */
    private static RunningResourceServer tlsResourceServer;

    /** Port of the TLS connector of the authorization server. */
    private static int tlsPort;

    /** Directory with the key files of the clients, deleted at the end. */
    private static Path keyDirectory;

    /** Self-signed client identity: the key store of an authority, whose certificate is its own issuer. */
    private static TestPki.Identity selfSignedClient;

    /**
     * Starts the applications: the authorization server with its TLS port (server certificate and trusted authority
     * from the test infrastructure), and a plain and a TLS resource server.
     *
     * @throws Exception if an application or the container cannot be started.
     */
    @BeforeAll
    static void startApplications() throws Exception {
        tlsPort = RunningAuthServer.freePort();
        keyDirectory = Files.createTempDirectory("e2e-client-keys");
        selfSignedClient = selfSigned(SELF_SIGNED_PKI);
        authServer = RunningAuthServer.start(List.of(
                "--authserver.clients.bff.redirect-uris=" + BFF_REDIRECT_URI,
                "--authserver.x509.enabled=true",
                "--authserver.x509.port=" + tlsPort,
                "--authserver.x509.key-store=" + SERVER.keyStore(),
                "--authserver.x509.key-store-password=" + SERVER.password(),
                "--authserver.mtls.trusted-authorities[0]=" + authorityPem()));
        admin = new ClientAdminApi(authServer);
        plainResourceServer = RunningResourceServer.start(authServer.issuer());
        tlsResourceServer = RunningResourceServer.startWithTls(authServer.issuer(), SERVER);
    }

    /**
     * Stops the applications and removes the generated keys.
     *
     * @throws IOException if a key file cannot be removed.
     */
    @AfterAll
    static void stopApplications() throws IOException {
        if (plainResourceServer != null) {
            plainResourceServer.close();
        }
        if (tlsResourceServer != null) {
            tlsResourceServer.close();
        }
        if (authServer != null) {
            authServer.close();
        }
        if (keyDirectory != null) {
            try (var files = Files.list(keyDirectory)) {
                for (final var file : files.toList()) {
                    Files.delete(file);
                }
            }
            Files.delete(keyDirectory);
        }
        PKI.close();
        SELF_SIGNED_PKI.close();
    }

    /**
     * Verifies that the tool reads the documents with a token obtained through {@code client_secret_basic}.
     *
     * @throws Exception if a step fails.
     */
    @Test
    void clientCredentials_whenTheClientAuthenticatesWithASecret_theToolReadsTheDocuments() throws Exception {
        final var clientId = "e2e-secret-basic-" + UUID.randomUUID();
        final var secret = admin.create(ClientAdminApi.confidentialClient(clientId, List.of("client_secret_basic"),
                List.of(CLIENT_CREDENTIALS)));
        assertNotNull(secret, "a client_secret_basic client is given a generated secret");

        final var run = run(clientId, secret, "client_secret_basic", authServer.issuer() + "/oauth2/token",
                plainResourceServer, List.of(), List.of());

        assertCompleted(run);
        final var claims = JwtClaims.of(run.accessToken());
        assertEquals(clientId, claims.get("sub").asString());
        assertFalse(claims.has(CNF), "an unbound token has no confirmation claim");
    }

    /**
     * Verifies that the tool reads the documents with a token obtained through {@code private_key_jwt}, signing its
     * assertion with a key pair generated for this test whose public half is the only thing the server stores.
     *
     * @throws Exception if a step fails.
     */
    @Test
    void clientCredentials_whenTheClientAuthenticatesWithAPrivateKeyJwt_theToolReadsTheDocuments() throws Exception {
        final var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(RSA_KEY_BITS);
        final var pair = generator.generateKeyPair();
        final var keyFile = keyDirectory.resolve("private-key-" + UUID.randomUUID() + ".pem");
        Files.writeString(keyFile, PublicJwks.privateKeyPem(pair.getPrivate().getEncoded()));
        final var clientId = "e2e-private-key-jwt-" + UUID.randomUUID();
        final var definition = ClientAdminApi.confidentialClient(clientId, List.of("private_key_jwt"),
                List.of(CLIENT_CREDENTIALS));
        definition.set("jwks", PublicJwks.rsa((RSAPublicKey) pair.getPublic()));
        definition.put("tokenEndpointAuthSigningAlgorithm", "RS256");
        assertNull(admin.create(definition), "a private_key_jwt client has no secret");

        final var run = run(clientId, null, "private_key_jwt", authServer.issuer() + "/oauth2/token",
                plainResourceServer, List.of("--service-client.auth.key.private-key-path=" + keyFile), List.of());

        assertCompleted(run);
        assertEquals(clientId, JwtClaims.of(run.accessToken()).get("sub").asString());
    }

    /**
     * Verifies {@code tls_client_auth}: the client presents a certificate issued by the authority configured in
     * {@code authserver.mtls.trusted-authorities}, and gets a token bound to it, which the TLS resource server accepts
     * from the tool. The printed token, replayed without the certificate, is refused.
     *
     * @throws Exception if a step fails.
     */
    @Test
    void clientCredentials_whenTheClientPresentsACertificateOfATrustedAuthority_theTokenIsBoundToTheCertificate()
            throws Exception {
        final var clientId = "e2e-tls-client-auth-" + UUID.randomUUID();
        final var definition = ClientAdminApi.confidentialClient(clientId, List.of("tls_client_auth"),
                List.of(CLIENT_CREDENTIALS));
        definition.put("tlsClientAuthSubjectDn", TRUSTED_CLIENT.certificate().certificate()
                .getSubjectX500Principal().getName());
        definition.put("certificateBoundAccessTokens", true);
        assertNull(admin.create(definition), "a tls_client_auth client has no secret");

        final var run = run(clientId, null, "tls_client_auth", tlsTokenUri(), tlsResourceServer,
                sslBundleArguments(TRUSTED_CLIENT, ENTITY_ALIAS), sslBundleEnvironment(TRUSTED_CLIENT));

        assertCompleted(run);
        final var token = run.accessToken();
        final var claims = JwtClaims.of(token);
        assertEquals(clientId, claims.get("sub").asString());
        assertEquals(thumbprint(TRUSTED_CLIENT.certificate().certificate()),
                claims.get(CNF).get("x5t#S256").asString());
        assertEquals(HTTP_UNAUTHORIZED, listDocuments(PKI.clientContext(null), "Bearer " + token),
                "the bound token is refused without its certificate");
        assertEquals(HTTP_OK, listDocuments(PKI.clientContext(TRUSTED_CLIENT), "Bearer " + token),
                "the same token is accepted with its certificate");
    }

    /**
     * Verifies {@code self_signed_tls_client_auth}: the client presents a self-signed certificate whose public key is
     * registered in its JWK set.
     *
     * @throws Exception if a step fails.
     */
    @Test
    void clientCredentials_whenTheClientPresentsARegisteredSelfSignedCertificate_theToolReadsTheDocuments()
            throws Exception {
        final var clientId = "e2e-self-signed-" + UUID.randomUUID();
        final var definition = ClientAdminApi.confidentialClient(clientId, List.of("self_signed_tls_client_auth"),
                List.of(CLIENT_CREDENTIALS));
        definition.set("jwks", PublicJwks.p256(
                (ECPublicKey) selfSignedClient.certificate().certificate().getPublicKey()));
        assertNull(admin.create(definition), "a self_signed_tls_client_auth client has no secret");

        final var run = run(clientId, null, "self_signed_tls_client_auth", tlsTokenUri(), plainResourceServer,
                sslBundleArguments(selfSignedClient, AUTHORITY_ALIAS), sslBundleEnvironment(selfSignedClient));

        assertCompleted(run);
        assertEquals(clientId, JwtClaims.of(run.accessToken()).get("sub").asString());
    }

    /**
     * Verifies DPoP: the tool proves possession of a key it generates, the token is bound to it ({@code cnf.jkt}), and
     * the printed token, replayed as a bearer token or without a proof, is refused by the resource server.
     *
     * @throws Exception if a step fails.
     */
    @Test
    void clientCredentials_whenTheToolUsesDpop_theTokenIsBoundToItsKey() throws Exception {
        final var clientId = "e2e-dpop-" + UUID.randomUUID();
        final var secret = admin.create(ClientAdminApi.confidentialClient(clientId, List.of("client_secret_basic"),
                List.of(CLIENT_CREDENTIALS)));

        final var run = run(clientId, secret, "client_secret_basic", authServer.issuer() + "/oauth2/token",
                plainResourceServer, List.of(), List.of("SERVICE_CLIENT_DPOP=true"));

        assertCompleted(run);
        final var token = run.accessToken();
        assertTrue(JwtClaims.of(token).get(CNF).has("jkt"), "the token is bound to the DPoP key");
        final var plain = HttpClient.newHttpClient();
        assertEquals(HTTP_UNAUTHORIZED, listDocuments(plain, plainResourceServer, "Bearer " + token),
                "a DPoP-bound token is refused as a bearer token");
        assertEquals(HTTP_UNAUTHORIZED, listDocuments(plain, plainResourceServer, "DPoP " + token),
                "a DPoP-bound token is refused without a proof");
    }

    /**
     * Runs the tool with the profile {@code client-credentials}.
     *
     * @param clientId       identifier of the client.
     * @param secret         secret of the client, or {@code null} when it has none.
     * @param method         the client authentication method.
     * @param tokenUri       the token endpoint to use.
     * @param resourceServer the resource server to read from.
     * @param arguments      more program arguments.
     * @param environment    more {@code NAME=value} environment entries.
     * @return the run.
     * @throws Exception if the tool cannot be run.
     */
    private static ServiceClientRun run(final String clientId, final String secret, final String method,
                                        final String tokenUri, final RunningResourceServer resourceServer,
                                        final List<String> arguments, final List<String> environment)
            throws Exception {
        final var env = new ArrayList<>(List.of(
                "SERVICE_CLIENT_ID=" + clientId,
                "SERVICE_CLIENT_AUTH_METHOD=" + method,
                "SERVICE_CLIENT_TOKEN_URI=" + tokenUri,
                "SERVICE_CLIENT_RESOURCE_SERVER_URI=" + resourceServer.baseUri(),
                "SERVICE_CLIENT_PRINT_ACCESS_TOKEN=true"));
        if (secret != null) {
            env.add("SERVICE_CLIENT_SECRET=" + secret);
        }
        env.addAll(environment);
        return ServiceClientRun.run("client-credentials", arguments, env);
    }

    /**
     * Asserts that a run ended without error and printed an access token and no failure.
     *
     * @param run the run.
     */
    private static void assertCompleted(final ServiceClientRun run) {
        assertEquals(0, run.exitCode(), run.describe());
        assertNotNull(run.accessToken(), run.describe());
    }

    /**
     * Returns the program arguments that define the SSL bundle of the tool: the identity as key store and the
     * authority of the server certificates as trust store.
     *
     * @param identity the client identity.
     * @param alias    alias of the private key in the identity's key store.
     * @return the arguments, which carry no password.
     */
    private static List<String> sslBundleArguments(final TestPki.Identity identity, final String alias) {
        final var prefix = "--spring.ssl.bundle.jks." + BUNDLE + ".";
        return List.of(
                prefix + "keystore.location=" + ServiceClientRun.fileUrl(identity.keyStore()),
                prefix + "keystore.type=PKCS12",
                prefix + "key.alias=" + alias,
                prefix + "truststore.location=" + ServiceClientRun.fileUrl(SERVER.keyStore()),
                prefix + "truststore.type=PKCS12",
                "--service-client.auth.ssl-bundle=" + BUNDLE);
    }

    /**
     * Returns the environment entries that carry the passwords of the SSL bundle of the tool.
     *
     * @param identity the client identity.
     * @return the {@code NAME=value} entries.
     */
    private static List<String> sslBundleEnvironment(final TestPki.Identity identity) {
        final var prefix = "SPRING_SSL_BUNDLE_JKS_" + BUNDLE.toUpperCase(Locale.ROOT) + "_";
        return List.of(prefix + "KEYSTORE_PASSWORD=" + identity.password(),
                prefix + "TRUSTSTORE_PASSWORD=" + SERVER.password());
    }

    /**
     * Returns the token endpoint of the TLS port of the authorization server.
     *
     * @return the URI.
     */
    private static String tlsTokenUri() {
        return "https://localhost:" + tlsPort + "/oauth2/token";
    }

    /**
     * Lists the documents of the TLS resource server with an authorization header and a TLS context.
     *
     * @param context       the TLS context, with or without a client certificate.
     * @param authorization value of the {@code Authorization} header.
     * @return the HTTP status.
     * @throws Exception if the request fails.
     */
    private static int listDocuments(final SSLContext context, final String authorization)
            throws Exception {
        return listDocuments(HttpClient.newBuilder().sslContext(context).build(), tlsResourceServer, authorization);
    }

    /**
     * Lists the documents of a resource server.
     *
     * @param client        the HTTP client.
     * @param server        the resource server.
     * @param authorization value of the {@code Authorization} header.
     * @return the HTTP status.
     * @throws Exception if the request fails.
     */
    private static int listDocuments(final HttpClient client, final RunningResourceServer server,
                                     final String authorization) throws Exception {
        final var request = HttpRequest.newBuilder(server.documentsUri()).header("Authorization", authorization)
                .GET().build();
        return client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    /**
     * Computes the {@code x5t#S256} thumbprint of a certificate.
     *
     * @param certificate the certificate.
     * @return the unpadded base64url SHA-256 of its encoding.
     * @throws GeneralSecurityException if the certificate cannot be encoded.
     */
    private static String thumbprint(final X509Certificate certificate) throws GeneralSecurityException {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
    }

    /**
     * Returns the PEM file of the authority that issued the trusted client certificate.
     *
     * @return the path of the authority certificate.
     */
    private static Path authorityPem() {
        return TRUSTED_CLIENT.keyStore().getParent().resolve("ca.pem");
    }

    /**
     * Builds the identity of a self-signed certificate from the authority of a test infrastructure: its certificate is
     * its own issuer and its key store holds the private key under the alias {@code ca}.
     *
     * @param pki the test infrastructure.
     * @return the identity.
     */
    private static TestPki.Identity selfSigned(final TestPki pki) {
        final var directory = pki.issueClient("unused").keyStore().getParent();
        try {
            final var pem = Files.readString(directory.resolve("ca.pem"));
            final var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
            return new TestPki.Identity(directory.resolve("ca.p12"), Files.readString(directory.resolve("password")),
                    TestCertificates.of(certificate));
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Cannot read the self-signed certificate", e);
        }
    }
}
