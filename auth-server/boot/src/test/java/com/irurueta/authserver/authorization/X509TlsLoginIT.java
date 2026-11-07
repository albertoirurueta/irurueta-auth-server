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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.application.x509.BindCertificateUseCase;
import com.irurueta.authserver.authorization.application.x509.UnbindCertificateUseCase;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import com.irurueta.authserver.testsupport.PostgresIT;
import com.irurueta.authserver.testsupport.TestPki;
import java.io.IOException;
import java.net.CookieManager;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Checks the sign-in with a client certificate over TLS client authentication on the dedicated port, with a real
 * handshake: the server presents a certificate issued by an in-test certificate authority and asks the client for one;
 * a certificate bound to an account signs it in (the tokens report {@code sc}), and a certificate bound to nobody, one
 * whose binding was removed, one that expired and a client with no certificate at all are sent back to the login page.
 * The authority, the server and the client certificates are generated at run time and live in a temporary directory
 * that is removed afterwards; nothing is kept in the repository.
 */
@PostgresIT(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class X509TlsLoginIT {

    /** Path of the sign-in with a certificate. */
    private static final String X509_LOGIN = "/login/x509";

    /** Location of a failed sign-in. */
    private static final String FAILED = "/login?error";

    /** A page that needs a signed-in user. */
    private static final String PROTECTED_PAGE = "/account/passkeys";

    /** Status of a redirect. */
    private static final int FOUND = 302;

    /** Status of a successful answer. */
    private static final int OK = 200;

    /** Name of the response header with the location of a redirect. */
    private static final String LOCATION = "Location";

    /** The certificate authority of the test, generated for the run. */
    private static final TestPki PKI = TestPki.create("test-authority-" + UUID.randomUUID());

    /** The server's identity, generated for the run. */
    private static final TestPki.Identity SERVER = PKI.issueServer("localhost");

    /** The port of the TLS connector, free when the class loads. */
    private static final int TLS_PORT = freePort();

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Port that stores the users. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores the client registrations. */
    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    /** Binds a certificate to an account. */
    @Autowired
    private BindCertificateUseCase bindCertificateUseCase;

    /** Removes the binding of a certificate. */
    @Autowired
    private UnbindCertificateUseCase unbindCertificateUseCase;

    /**
     * Enables the sign-in with a certificate on the dedicated TLS port, with the server certificate of the test.
     *
     * @param registry registry of the properties of the context.
     */
    @DynamicPropertySource
    static void x509(final DynamicPropertyRegistry registry) {
        registry.add("authserver.x509.enabled", () -> "true");
        registry.add("authserver.x509.port", () -> TLS_PORT);
        registry.add("authserver.x509.key-store", () -> SERVER.keyStore().toString());
        registry.add("authserver.x509.key-store-password", SERVER::password);
    }

    /**
     * Removes the generated key stores.
     */
    @AfterAll
    static void removeKeys() {
        PKI.close();
    }

    /**
     * Verifies that a bound certificate signs its account in over TLS, resumes the authorization request and shows
     * as {@code sc} in the tokens, and that the session that results works on the TLS port.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheClientPresentsABoundCertificate_signsInAndTheTokensReportSc() throws Exception {
        final var fixtures = fixtures();
        final var user = fixtures.createUser();
        final var identity = PKI.issueClient("client-" + UUID.randomUUID());
        bind(user.username(), identity);
        final var client = fixtures.createCodeClient();
        final var verifier = AuthServerFixtures.randomValue() + AuthServerFixtures.randomValue();
        final var browser = browser(identity);

        final var asked = send(browser, UriComponentsBuilder
                .fromUriString(base() + AuthServerFixtures.authorizeUri(client, verifier, Map.of())).build().encode()
                .toUri());
        assertEquals(FOUND, asked.statusCode());
        final var resumed = send(browser, URI.create(base() + X509_LOGIN));
        assertEquals(FOUND, resumed.statusCode());
        final var authorizeUri = asked.uri().resolve(location(resumed));
        assertTrue(authorizeUri.getPath().endsWith("/oauth2/authorize"),
                "Expected to resume the request: " + authorizeUri);
        final var authorized = send(browser, authorizeUri);
        assertEquals(FOUND, authorized.statusCode());
        final var code = UriComponentsBuilder.fromUri(authorizeUri.resolve(location(authorized))).build()
                .getQueryParams().getFirst("code");
        assertNotNull(code);
        final var tokens = fixtures.exchangeCode(client, code, verifier);

        final var claims = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(List.of("sc"), claims.get("amr").valueStream().map(node -> node.asString()).toList());
        assertEquals(user.username(), claims.get("sub").asString());
        assertEquals(OK, send(browser, URI.create(base() + PROTECTED_PAGE)).statusCode());
    }

    /**
     * Verifies that a certificate issued by the authority but bound to nobody is sent back to the login page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheCertificateIsNotBound_redirectsToTheLoginPage() throws Exception {
        final var identity = PKI.issueClient("stranger-" + UUID.randomUUID());

        final var response = send(browser(identity), URI.create(base() + X509_LOGIN));

        assertFailed(response);
    }

    /**
     * Verifies that a client that presents no certificate is sent back to the login page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheClientPresentsNoCertificate_redirectsToTheLoginPage() throws Exception {
        final var response = send(browser(null), URI.create(base() + X509_LOGIN));

        assertFailed(response);
    }

    /**
     * Verifies that a certificate whose binding was removed signed the account in before and is refused afterwards.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheBindingWasRemoved_isRefused() throws Exception {
        final var user = fixtures().createUser();
        final var identity = PKI.issueClient("revoked-" + UUID.randomUUID());
        final var binding = bind(user.username(), identity);
        final var signedIn = send(browser(identity), URI.create(base() + X509_LOGIN));
        assertFalse(location(signedIn).endsWith(FAILED), "The bound certificate must sign in");
        unbindCertificateUseCase.execute(binding.userId(), user.username(), binding.id());

        final var response = send(browser(identity), URI.create(base() + X509_LOGIN));

        assertFailed(response);
    }

    /**
     * Verifies that a bound certificate that expired is refused: the handshake accepts any certificate, so the
     * application itself checks that the certificate is within its validity.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheBoundCertificateHasExpired_isRefused() throws Exception {
        final var user = fixtures().createUser();
        final var identity = PKI.issueExpiredClient("expired-" + UUID.randomUUID());
        bind(user.username(), identity);

        final var response = send(browser(identity), URI.create(base() + X509_LOGIN));

        assertFailed(response);
    }

    /**
     * Builds the helper that creates users and clients.
     *
     * @return the fixtures.
     */
    private AuthServerFixtures fixtures() {
        return new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
    }

    /**
     * Binds the certificate of an identity to an account.
     *
     * @param username name of the account.
     * @param identity the identity.
     * @return the binding.
     */
    private CertificateBinding bind(final String username, final TestPki.Identity identity) {
        final var account = userAccounts.findByUsername(username).orElseThrow();
        return bindCertificateUseCase.execute(account.id(), username, identity.certificate().fingerprintSha256(),
                "CN=test");
    }

    /**
     * Builds a browser that talks TLS with the given identity and keeps its cookies.
     *
     * @param identity the certificate it presents, {@code null} for none.
     * @return the browser.
     */
    private static HttpClient browser(final TestPki.Identity identity) {
        return HttpClient.newBuilder().sslContext(PKI.clientContext(identity)).cookieHandler(new CookieManager())
                .followRedirects(HttpClient.Redirect.NEVER).build();
    }

    /**
     * Performs a request without following redirects.
     *
     * @param browser the browser.
     * @param uri     the address.
     * @return the answer.
     * @throws IOException          if the request fails.
     * @throws InterruptedException if the thread is interrupted.
     */
    private static HttpResponse<String> send(final HttpClient browser, final URI uri)
            throws IOException, InterruptedException {
        return browser.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Reads the location of a redirect.
     *
     * @param response the answer.
     * @return the location.
     */
    private static String location(final HttpResponse<String> response) {
        return response.headers().firstValue(LOCATION).orElse("");
    }

    /**
     * Checks that an answer sends the browser back to the login page with an error.
     *
     * @param response the answer.
     */
    private static void assertFailed(final HttpResponse<String> response) {
        assertEquals(FOUND, response.statusCode());
        assertTrue(location(response).endsWith(FAILED), "Expected a failed sign-in but got " + location(response));
    }

    /**
     * Gives the address of the TLS port.
     *
     * @return the base URL.
     */
    private static String base() {
        return "https://localhost:" + TLS_PORT;
    }

    /**
     * Finds a free port.
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
}
