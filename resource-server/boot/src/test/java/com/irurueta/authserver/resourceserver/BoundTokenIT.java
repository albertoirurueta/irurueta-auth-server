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

package com.irurueta.authserver.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.testsupport.TestPki;
import com.nimbusds.jose.jwk.ECKey;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Integration tests of the sender-constrained tokens the resource server accepts, over a real TLS handshake: the
 * server presents a certificate issued by an in-test authority and asks the client for one
 * ({@code server.ssl.client-auth=want}), so a token bound to a certificate ({@code cnf.x5t#S256}, RFC 8705) is only
 * accepted from the connection that presents that certificate, and a token bound to a key ({@code cnf.jkt}, RFC 9449)
 * only with a DPoP proof signed by it, never as a plain bearer token. Every key and certificate is generated at run
 * time; the key store of the server doubles as its trust store because it also holds the authority's certificate.
 * TLS is pinned to 1.2 because the JSSE implementation of TLS 1.3 has no post-handshake authentication, which
 * optional client authentication needs, so a client certificate would never reach the server.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class BoundTokenIT {

    /** Issuer claim of the test tokens. */
    private static final String ISSUER = "http://localhost:9000";

    /** Subject of the test tokens. */
    private static final String SUBJECT = "demo";

    /** Audience the resource server accepts. */
    private static final List<String> AUDIENCES = List.of("resource-server");

    /** Scope of the test tokens. */
    private static final String SCOPE = "documents.read";

    /** Status of a successful answer. */
    private static final int OK = 200;

    /** Status of a refused token. */
    private static final int UNAUTHORIZED = 401;

    /** The certificate authority of the test, generated for the run. */
    private static final TestPki PKI = TestPki.create("test-authority-" + UUID.randomUUID());

    /** The server's identity, generated for the run. */
    private static final TestPki.Identity SERVER = PKI.issueServer("localhost");

    /** The identity of the client the tokens are bound to. */
    private static final TestPki.Identity CLIENT = PKI.issueClient("bound-client");

    /** Another identity, trusted by the same authority. */
    private static final TestPki.Identity OTHER_CLIENT = PKI.issueClient("other-client");

    /** Port of the running server. */
    @LocalServerPort
    private int port;

    /**
     * Points the decoder at the generated signing key and turns TLS with optional client authentication on.
     *
     * @param registry registry of the test properties.
     * @throws IOException if the PEM file cannot be written.
     */
    @DynamicPropertySource
    static void tls(final DynamicPropertyRegistry registry) throws IOException {
        TestTokens.publicKeyLocation(registry);
        registry.add("server.ssl.key-store", () -> SERVER.keyStore().toString());
        registry.add("server.ssl.key-store-password", SERVER::password);
        registry.add("server.ssl.key-store-type", () -> "PKCS12");
        registry.add("server.ssl.key-alias", () -> "entity");
        registry.add("server.ssl.trust-store", () -> SERVER.keyStore().toString());
        registry.add("server.ssl.trust-store-password", SERVER::password);
        registry.add("server.ssl.trust-store-type", () -> "PKCS12");
        registry.add("server.ssl.client-auth", () -> "want");
        registry.add("server.ssl.enabled-protocols", () -> "TLSv1.2");
    }

    /**
     * Removes the generated key stores.
     */
    @AfterAll
    static void removeKeys() {
        PKI.close();
    }

    /**
     * A certificate-bound token sent over the connection that presents its certificate is accepted.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenCertificateBoundTokenComesWithItsCertificate_returnsOk() throws Exception {
        final var response = get(CLIENT, certificateBoundToken(CLIENT), null);

        assertEquals(OK, response.statusCode());
        assertEquals(SUBJECT, response.body());
    }

    /**
     * A certificate-bound token sent over a connection without a client certificate is refused.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenCertificateBoundTokenComesWithoutCertificate_returnsUnauthorized() throws Exception {
        final var response = get(null, certificateBoundToken(CLIENT), null);

        assertEquals(UNAUTHORIZED, response.statusCode());
    }

    /**
     * A certificate-bound token sent with another certificate is refused.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenCertificateBoundTokenComesWithAnotherCertificate_returnsUnauthorized()
            throws Exception {
        final var response = get(OTHER_CLIENT, certificateBoundToken(CLIENT), null);

        assertEquals(UNAUTHORIZED, response.statusCode());
    }

    /**
     * A DPoP-bound token with a valid proof is accepted.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenDpopBoundTokenComesWithValidProof_returnsOk() throws Exception {
        final var key = TestTokens.dpopKey();
        final var token = dpopBoundToken(key);
        final var proof = TestTokens.dpopProof(key, "GET", url(), token);

        final var response = get(null, "DPoP " + token, proof);

        assertEquals(OK, response.statusCode());
        assertEquals(SUBJECT, response.body());
    }

    /**
     * A DPoP-bound token sent as a plain bearer token is refused, even with a proof.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenDpopBoundTokenIsSentAsBearer_returnsUnauthorized() throws Exception {
        final var key = TestTokens.dpopKey();
        final var token = dpopBoundToken(key);
        final var proof = TestTokens.dpopProof(key, "GET", url(), token);

        final var response = get(null, "Bearer " + token, proof);

        assertEquals(UNAUTHORIZED, response.statusCode());
    }

    /**
     * A DPoP-bound token sent with the DPoP scheme but no proof is refused.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenDpopBoundTokenComesWithoutProof_returnsUnauthorized() throws Exception {
        final var response = get(null, "DPoP " + dpopBoundToken(TestTokens.dpopKey()), null);

        assertEquals(UNAUTHORIZED, response.statusCode());
    }

    /**
     * A proof signed by another key than the one the token is bound to is refused.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenProofIsSignedByAnotherKey_returnsUnauthorized() throws Exception {
        final var token = dpopBoundToken(TestTokens.dpopKey());
        final var proof = TestTokens.dpopProof(TestTokens.dpopKey(), "GET", url(), token);

        final var response = get(null, "DPoP " + token, proof);

        assertEquals(UNAUTHORIZED, response.statusCode());
    }

    /**
     * Builds a token bound to the certificate of an identity.
     *
     * @param identity the identity.
     * @return the value of the {@code Authorization} header carrying the compact token as a bearer token.
     */
    private static String certificateBoundToken(final TestPki.Identity identity) {
        return "Bearer " + TestTokens.tokenValue(ISSUER, SUBJECT, AUDIENCES, SCOPE, List.of(),
                TestTokens.certificateBound(identity.certificate().certificate()));
    }

    /**
     * Builds a token bound to a DPoP key.
     *
     * @param key the key.
     * @return the compact token.
     */
    private static String dpopBoundToken(final ECKey key) {
        return TestTokens.tokenValue(ISSUER, SUBJECT, AUDIENCES, SCOPE, List.of(), TestTokens.dpopBound(key));
    }

    /**
     * Gives the URL of the protected endpoint.
     *
     * @return the URL.
     */
    private String url() {
        return "https://localhost:" + port + ProtectedTestController.PATH;
    }

    /**
     * Calls the protected endpoint.
     *
     * @param identity      identity the client presents, {@code null} for none.
     * @param authorization value of the {@code Authorization} header.
     * @param proof         value of the {@code DPoP} header, {@code null} for none.
     * @return the response.
     * @throws Exception if the request cannot be performed.
     */
    private HttpResponse<String> get(final TestPki.Identity identity, final String authorization,
                                     final String proof) throws Exception {
        final var request = HttpRequest.newBuilder(URI.create(url())).header("Authorization", authorization);
        if (proof != null) {
            request.header("DPoP", proof);
        }
        try (var client = HttpClient.newBuilder().sslContext(PKI.clientContext(identity)).build()) {
            return client.send(request.GET().build(), HttpResponse.BodyHandlers.ofString());
        }
    }
}
