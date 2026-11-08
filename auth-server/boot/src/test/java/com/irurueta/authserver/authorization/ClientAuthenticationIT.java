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
package com.irurueta.authserver.authorization;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import com.irurueta.authserver.testsupport.TestCertificates;
import com.irurueta.authserver.testsupport.TestPki;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Checks the client authentication methods of the token endpoint against the running application: the shared secret,
 * {@code private_key_jwt} with registered keys and with a {@code jwkSetUrl} served by WireMock (and the refusal of a
 * replayed or over-long assertion), {@code tls_client_auth} with a certificate issued by the configured authority (and
 * the refusal of a self-issued one with the same DN), {@code self_signed_tls_client_auth}, the certificate-bound access
 * token ({@code cnf.x5t#S256}) and the DPoP proof at the token endpoint ({@code token_type=DPoP}, {@code cnf.jkt}).
 * The mutual-TLS calls are real handshakes against the dedicated TLS port. The authorities, certificates and keys are
 * generated when the test runs and live in temporary directories removed afterwards; nothing is kept in the repository.
 */
@PostgresIT(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ClientAuthenticationIT {

    /** Path of the token endpoint. */
    private static final String TOKEN_PATH = "/oauth2/token";

    /** Path of the JWK set that WireMock serves. */
    private static final String JWKS_PATH = "/jwks.json";

    /** Name of the client the certificates are issued to; it is also the common name of their subject. */
    private static final String CERTIFICATE_NAME = "mtls-client";

    /** Scope every test client may request. */
    private static final String SCOPE = "documents.read";

    /** Type of the client assertions. */
    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /** Name of the answer field that carries the access token. */
    private static final String ACCESS_TOKEN = "access_token";

    /** Name of the {@code cnf} claim. */
    private static final String CNF = "cnf";

    /** Status of a successful answer. */
    private static final int OK = 200;

    /** Status of a refused client authentication. */
    private static final int UNAUTHORIZED = 401;

    /** Longest assertion lifetime accepted by the server, in minutes. */
    private static final long MAX_LIFETIME_MINUTES = 5L;

    /** Lifetime of a well-behaved assertion. */
    private static final Duration SHORT_LIFETIME = Duration.ofMinutes(1);

    /** Lifetime of an assertion that lives longer than the server accepts. */
    private static final Duration LONG_LIFETIME = Duration.ofMinutes(MAX_LIFETIME_MINUTES * 2);

    /** Lifetime of the access tokens of the test clients. */
    private static final Duration TOKEN_TTL = Duration.ofMinutes(10);

    /** Lifetime of the refresh tokens of the test clients. */
    private static final Duration REFRESH_TTL = Duration.ofHours(1);

    /** The authority that issues the server and the trusted client certificates, generated for the run. */
    private static final TestPki PKI = TestPki.create("client-auth-authority-" + UUID.randomUUID());

    /** An authority the server does not trust, which issues the look-alike client certificate. */
    private static final TestPki ROGUE_PKI = TestPki.create("rogue-authority-" + UUID.randomUUID());

    /** A source of a self-signed certificate: its authority is itself self-signed and has a key. */
    private static final TestPki SELF_SIGNED_PKI = TestPki.create("self-signed-client-" + UUID.randomUUID());

    /** The identity of the server. */
    private static final TestPki.Identity SERVER = PKI.issueServer("localhost");

    /** The certificate the trusted client presents. */
    private static final TestPki.Identity TRUSTED_CLIENT = PKI.issueClient(CERTIFICATE_NAME);

    /** A certificate with the same subject as the trusted one, issued by the authority the server does not trust. */
    private static final TestPki.Identity LOOK_ALIKE_CLIENT = ROGUE_PKI.issueClient(CERTIFICATE_NAME);

    /** The identity of the client that signs its own certificate. */
    private static final TestPki.Identity SELF_SIGNED_CLIENT = selfSigned(SELF_SIGNED_PKI);

    /** Serves the JWK sets of the clients registered with a {@code jwkSetUrl}. */
    private static final WireMockServer JWKS_SERVER = new WireMockServer(WireMockConfiguration.options()
            .dynamicPort());

    /** The port of the TLS connector. */
    private static final int TLS_PORT = freePort();

    /** The port of the application's main connector. */
    @LocalServerPort
    private int port;

    /** The issuer identifier of the server, whose token endpoint is the audience of a client assertion. */
    @Value("${spring.security.oauth2.authorizationserver.issuer}")
    private String issuer;

    /** Port that stores the client registrations. */
    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Starts WireMock and points the application at the generated certificates.
     *
     * @param registry the properties of the application context.
     */
    @DynamicPropertySource
    static void clientAuthentication(final DynamicPropertyRegistry registry) {
        JWKS_SERVER.start();
        registry.add("authserver.x509.enabled", () -> "true");
        registry.add("authserver.x509.port", () -> TLS_PORT);
        registry.add("authserver.x509.key-store", () -> SERVER.keyStore().toString());
        registry.add("authserver.x509.key-store-password", SERVER::password);
        registry.add("authserver.mtls.trusted-authorities[0]", () -> authorityPem(TRUSTED_CLIENT).toString());
    }

    /**
     * Stops WireMock and removes the generated key stores.
     */
    @AfterAll
    static void tearDown() {
        JWKS_SERVER.stop();
        PKI.close();
        ROGUE_PKI.close();
        SELF_SIGNED_PKI.close();
    }

    /**
     * Verifies that the shared secret still authenticates a client.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenClientSecretBasicIsCorrect_issuesAToken() throws Exception {
        final var clientId = register(List.of("client_secret_basic"), null, null, null, null, false, "secret-value");
        final var basic = "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":secret-value").getBytes(StandardCharsets.UTF_8));

        final var response = postForm(plainClient(), plainTokenUri(), Map.of("grant_type", "client_credentials",
                "scope", SCOPE), Map.of("Authorization", basic));

        assertEquals(OK, response.statusCode());
        assertTrue(AuthServerFixtures.parse(response.body()).has(ACCESS_TOKEN));
    }

    /**
     * Verifies that a wrong secret is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenClientSecretBasicIsWrong_isRefused() throws Exception {
        final var clientId = register(List.of("client_secret_basic"), null, null, null, null, false, "secret-value");
        final var basic = "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":wrong").getBytes(StandardCharsets.UTF_8));

        final var response = postForm(plainClient(), plainTokenUri(), Map.of("grant_type", "client_credentials",
                "scope", SCOPE), Map.of("Authorization", basic));

        assertEquals(UNAUTHORIZED, response.statusCode());
    }

    /**
     * Verifies that an assertion signed by a registered key authenticates the client.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenPrivateKeyJwtUsesRegisteredJwks_issuesAToken() throws Exception {
        final var key = new ECKeyGenerator(Curve.P_256).keyID("registered").generate();
        final var clientId = register(List.of("private_key_jwt"), null, new JWKSet(key.toPublicJWK()).toString(),
                "ES256", null, false, null);

        final var response = assertionRequest(clientId, key, UUID.randomUUID().toString(), SHORT_LIFETIME);

        assertEquals(OK, response.statusCode());
        assertTrue(AuthServerFixtures.parse(response.body()).has(ACCESS_TOKEN));
    }

    /**
     * Verifies that a client with a {@code jwkSetUrl} authenticates with a key that WireMock serves.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenPrivateKeyJwtUsesJwkSetUrl_issuesAToken() throws Exception {
        final var key = new ECKeyGenerator(Curve.P_256).keyID("served").generate();
        final var path = "/" + UUID.randomUUID() + JWKS_PATH;
        JWKS_SERVER.stubFor(get(urlPathEqualTo(path)).willReturn(aResponse().withStatus(OK)
                .withHeader("Content-Type", "application/json").withBody(new JWKSet(key.toPublicJWK()).toString())));
        final var clientId = register(List.of("private_key_jwt"), JWKS_SERVER.baseUrl() + path, null, "ES256", null,
                false, null);

        final var response = assertionRequest(clientId, key, UUID.randomUUID().toString(), SHORT_LIFETIME);

        assertEquals(OK, response.statusCode());
    }

    /**
     * Verifies that an assertion cannot be used twice.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenAssertionIsReplayed_isRefusedWithInvalidClient() throws Exception {
        final var key = new ECKeyGenerator(Curve.P_256).keyID("replay").generate();
        final var clientId = register(List.of("private_key_jwt"), null, new JWKSet(key.toPublicJWK()).toString(),
                "ES256", null, false, null);
        final var jti = UUID.randomUUID().toString();

        final var first = assertionRequest(clientId, key, jti, SHORT_LIFETIME);
        final var replay = assertionRequest(clientId, key, jti, SHORT_LIFETIME);

        assertEquals(OK, first.statusCode());
        assertEquals(UNAUTHORIZED, replay.statusCode());
        assertEquals("invalid_client", AuthServerFixtures.parse(replay.body()).get("error").asString());
    }

    /**
     * Verifies that an assertion that lives longer than the configured maximum is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenAssertionLivesTooLong_isRefusedWithInvalidClient() throws Exception {
        final var key = new ECKeyGenerator(Curve.P_256).keyID("long").generate();
        final var clientId = register(List.of("private_key_jwt"), null, new JWKSet(key.toPublicJWK()).toString(),
                "ES256", null, false, null);

        final var response = assertionRequest(clientId, key, UUID.randomUUID().toString(), LONG_LIFETIME);

        assertEquals(UNAUTHORIZED, response.statusCode());
        assertEquals("invalid_client", AuthServerFixtures.parse(response.body()).get("error").asString());
    }

    /**
     * Verifies that a certificate issued by the trusted authority, with the registered DN, authenticates the client.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenTlsClientAuthCertificateIsIssuedByTheTrustedAuthority_issuesAToken() throws Exception {
        final var clientId = register(List.of("tls_client_auth"), null, null, null, subjectDn(TRUSTED_CLIENT), false,
                null);

        final var response = tlsRequest(TRUSTED_CLIENT, clientId, Map.of());

        assertEquals(OK, response.statusCode());
        assertTrue(AuthServerFixtures.parse(response.body()).has(ACCESS_TOKEN));
    }

    /**
     * Verifies that a certificate with the same DN, issued by an authority the server does not trust, is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenTlsClientAuthCertificateIsIssuedByAnUntrustedAuthority_isRefused() throws Exception {
        final var clientId = register(List.of("tls_client_auth"), null, null, null, subjectDn(TRUSTED_CLIENT), false,
                null);

        final var response = tlsRequest(LOOK_ALIKE_CLIENT, clientId, Map.of());

        assertEquals(UNAUTHORIZED, response.statusCode());
    }

    /**
     * Verifies that a self-signed certificate whose key is registered authenticates the client.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenSelfSignedCertificateKeyIsRegistered_issuesAToken() throws Exception {
        final var jwks = new JWKSet(ecKeyOf(SELF_SIGNED_CLIENT.certificate().certificate())).toString();
        final var clientId = register(List.of("self_signed_tls_client_auth"), null, jwks, null, null, false, null);

        final var response = tlsRequest(SELF_SIGNED_CLIENT, clientId, Map.of());

        assertEquals(OK, response.statusCode());
    }

    /**
     * Verifies that a self-signed certificate whose key is not the registered one is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenSelfSignedCertificateKeyIsNotRegistered_isRefused() throws Exception {
        final var other = new ECKeyGenerator(Curve.P_256).generate();
        final var clientId = register(List.of("self_signed_tls_client_auth"), null,
                new JWKSet(other.toPublicJWK()).toString(), null, null, false, null);

        final var response = tlsRequest(SELF_SIGNED_CLIENT, clientId, Map.of());

        assertEquals(UNAUTHORIZED, response.statusCode());
    }

    /**
     * Verifies that the access token of a client with certificate-bound tokens carries the SHA-256 thumbprint of the
     * certificate.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenCertificateBoundAccessTokensAreEnabled_carriesTheCertificateThumbprint() throws Exception {
        final var clientId = register(List.of("tls_client_auth"), null, null, null, subjectDn(TRUSTED_CLIENT), true,
                null);

        final var response = tlsRequest(TRUSTED_CLIENT, clientId, Map.of());

        assertEquals(OK, response.statusCode());
        final var claims = AuthServerFixtures.claimsOf(AuthServerFixtures.parse(response.body())
                .get(ACCESS_TOKEN).asString());
        final var expected = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest
                .getInstance("SHA-256").digest(TRUSTED_CLIENT.certificate().certificate().getEncoded()));
        assertEquals(expected, claims.get(CNF).get("x5t#S256").asString());
    }

    /**
     * Verifies that a DPoP proof at the token endpoint gives a {@code DPoP} token bound to the proof key.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void token_whenADpopProofIsSent_issuesADpopTokenBoundToTheProofKey() throws Exception {
        final var clientId = register(List.of("client_secret_basic"), null, null, null, null, false, "secret-value");
        final var basic = "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":secret-value").getBytes(StandardCharsets.UTF_8));
        final var proofKey = new ECKeyGenerator(Curve.P_256).generate();

        final var response = postForm(plainClient(), plainTokenUri(), Map.of("grant_type", "client_credentials",
                "scope", SCOPE), Map.of("Authorization", basic, "DPoP", dpopProof(proofKey, plainTokenUri())));

        assertEquals(OK, response.statusCode());
        final var body = AuthServerFixtures.parse(response.body());
        assertEquals("DPoP", body.get("token_type").asString());
        final var claims = AuthServerFixtures.claimsOf(body.get(ACCESS_TOKEN).asString());
        assertEquals(proofKey.computeThumbprint().toString(), claims.get(CNF).get("jkt").asString());
    }

    /**
     * Sends a client credentials request authenticated with a signed assertion.
     *
     * @param clientId the client.
     * @param key      the key that signs.
     * @param jti      the identifier of the assertion.
     * @param lifetime the lifetime of the assertion.
     * @return the answer.
     * @throws IOException          if the request fails.
     * @throws InterruptedException if the request is interrupted.
     * @throws JOSEException        if the assertion cannot be signed.
     */
    private HttpResponse<String> assertionRequest(final String clientId, final ECKey key, final String jti,
            final Duration lifetime) throws IOException, InterruptedException, JOSEException {
        final var now = Instant.now();
        final var claims = new JWTClaimsSet.Builder().issuer(clientId).subject(clientId)
                .audience(issuer + TOKEN_PATH).jwtID(jti).issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(lifetime))).build();
        final var assertion = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(),
                claims);
        assertion.sign(new ECDSASigner(key));
        return postForm(plainClient(), plainTokenUri(), Map.of("grant_type", "client_credentials", "scope", SCOPE,
                "client_id", clientId, "client_assertion_type", ASSERTION_TYPE,
                "client_assertion", assertion.serialize()), Map.of());
    }

    /**
     * Sends a client credentials request over the TLS port presenting a certificate.
     *
     * @param identity the certificate to present.
     * @param clientId the client that authenticates.
     * @param headers  extra headers.
     * @return the answer.
     * @throws IOException          if the request fails.
     * @throws InterruptedException if the request is interrupted.
     */
    private HttpResponse<String> tlsRequest(final TestPki.Identity identity, final String clientId,
            final Map<String, String> headers) throws IOException, InterruptedException {
        final var client = HttpClient.newBuilder().sslContext(PKI.clientContext(identity)).build();
        return postForm(client, URI.create("https://localhost:" + TLS_PORT + TOKEN_PATH),
                Map.of("grant_type", "client_credentials", "scope", SCOPE, "client_id", clientId), headers);
    }

    /**
     * Builds a DPoP proof for the token endpoint.
     *
     * @param key the proof key.
     * @param uri the address of the token endpoint.
     * @return the serialized proof.
     * @throws JOSEException if the proof cannot be signed.
     */
    private static String dpopProof(final ECKey key, final URI uri) throws JOSEException {
        final var claims = new JWTClaimsSet.Builder().jwtID(UUID.randomUUID().toString()).claim("htm", "POST")
                .claim("htu", uri.toString()).issueTime(new Date()).build();
        final var proof = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt"))
                .jwk(key.toPublicJWK()).build(), claims);
        proof.sign(new ECDSASigner(key));
        return proof.serialize();
    }

    /**
     * Posts a form.
     *
     * @param client  the HTTP client.
     * @param uri     the address.
     * @param form    the form fields.
     * @param headers the extra headers.
     * @return the answer.
     * @throws IOException          if the request fails.
     * @throws InterruptedException if the request is interrupted.
     */
    private static HttpResponse<String> postForm(final HttpClient client, final URI uri,
            final Map<String, String> form, final Map<String, String> headers)
            throws IOException, InterruptedException {
        final var body = form.entrySet().stream().map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8)
                + "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&"));
        final var request = HttpRequest.newBuilder(uri).header("Content-Type", "application/x-www-form-urlencoded");
        new LinkedHashMap<>(headers).forEach(request::header);
        return client.send(request.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Registers a client credentials client.
     *
     * @param authMethods   the client authentication methods.
     * @param jwkSetUrl     the URL of the client's JWK set, or {@code null}.
     * @param jwks          the registered JWK set, or {@code null}.
     * @param algorithm     the assertion signing algorithm, or {@code null}.
     * @param subjectDn     the registered certificate subject DN, or {@code null}.
     * @param certificateBound whether the access tokens are bound to the certificate.
     * @param secret        the client secret, or {@code null} for none.
     * @return the identifier of the client.
     */
    private String register(final List<String> authMethods, final String jwkSetUrl, final String jwks,
            final String algorithm, final String subjectDn, final boolean certificateBound, final String secret) {
        final var clientId = "client-" + UUID.randomUUID();
        clientRegistrations.save(new ClientRegistration(clientId, "Client authentication test", true, authMethods,
                List.of("client_credentials"), List.of(), List.of(SCOPE), true, List.of("resource-server"),
                TOKEN_TTL, REFRESH_TTL, ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false,
                jwkSetUrl, jwks, algorithm, subjectDn, certificateBound),
                secret == null ? null : passwordEncoder.encode(secret));
        return clientId;
    }

    /**
     * Gives the subject DN of an identity's certificate, as the framework compares it.
     *
     * @param identity the identity.
     * @return the DN.
     */
    private static String subjectDn(final TestPki.Identity identity) {
        return identity.certificate().certificate().getSubjectX500Principal().getName();
    }

    /**
     * Converts the public key of a certificate to an EC JWK.
     *
     * @param certificate the certificate.
     * @return the public JWK.
     */
    private static ECKey ecKeyOf(final X509Certificate certificate) {
        final var key = (ECPublicKey) certificate.getPublicKey();
        return new ECKey.Builder(Curve.forECParameterSpec(key.getParams()), key).build();
    }

    /**
     * Finds the PEM file of the authority next to an identity's key store.
     *
     * @param identity an identity issued by the authority.
     * @return the file.
     */
    private static Path authorityPem(final TestPki.Identity identity) {
        return identity.keyStore().getParent().resolve("ca.pem");
    }

    /**
     * Builds the identity of a client that signs its own certificate: the self-signed certificate and key of the
     * authority of a throw-away infrastructure.
     *
     * @param pki the infrastructure whose authority is used.
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

    /**
     * Finds a free TCP port.
     *
     * @return the port.
     */
    private static int freePort() {
        try (var socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (final IOException e) {
            throw new IllegalStateException("No free port", e);
        }
    }

    /**
     * Gives the address of the token endpoint on the main port.
     *
     * @return the address.
     */
    private URI plainTokenUri() {
        return URI.create("http://localhost:" + port + TOKEN_PATH);
    }

    /**
     * Gives an HTTP client for the main port.
     *
     * @return the client.
     */
    private static HttpClient plainClient() {
        return HttpClient.newHttpClient();
    }
}
