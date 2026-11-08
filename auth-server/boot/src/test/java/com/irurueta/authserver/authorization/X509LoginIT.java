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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.application.x509.BindCertificateUseCase;
import com.irurueta.authserver.authorization.application.x509.UnbindCertificateUseCase;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import com.irurueta.authserver.testsupport.PostgresIT;
import com.irurueta.authserver.testsupport.TestCertificates;
import com.irurueta.authserver.testsupport.TestPki;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriUtils;

/**
 * Checks the sign-in with a client certificate as the whole application wires it, with the forwarded-certificate
 * transport enabled for a proxy at the loopback address (the address MockMvc requests come from): the login page offers
 * the button that posts to {@code POST /login/x509}, a bound certificate posted with the CSRF token signs its account
 * in, resumes the interrupted authorization request and shows in the tokens as {@code sc}; a
 * certificate bound to nobody, a request without a certificate, a header from an address nobody trusts and a disabled
 * account are all sent back to the login page, signed in as nobody, and neither a {@code GET} of the path nor a post
 * without the CSRF token ever signs anybody in. Every certificate is generated at run time.
 */
@PostgresIT
@AutoConfigureMockMvc
class X509LoginIT {

    /** Name of the header the proxy forwards the certificate in. */
    private static final String HEADER = "X-Client-Cert";

    /** Path of the sign-in with a certificate. */
    private static final String X509_LOGIN = "/login/x509";

    /** Location of a failed sign-in. */
    private static final String FAILED = "/login?error";

    /** An address that is not the proxy. */
    private static final String UNTRUSTED = "198.51.100.7";

    /** Name of the response header with the location of a redirect. */
    private static final String LOCATION = "Location";

    /** A page that needs a signed-in user. */
    private static final String PROTECTED_PAGE = "/account/passkeys";

    /** Status of a refused request. */
    private static final int FORBIDDEN = 403;

    /** The form of the certificate sign-in on the login page: its opening tag and its content. */
    private static final Pattern X509_FORM = Pattern.compile("<form([^>]*class=\"x509-login\"[^>]*)>(.*?)</form>",
            Pattern.DOTALL);

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

    /** Builds the users and clients. */
    private AuthServerFixtures fixtures;

    /** A certificate generated for the run. */
    private TestCertificates.GeneratedCertificate certificate;

    /**
     * Enables the sign-in with a certificate, forwarded by a proxy at the loopback address.
     *
     * @param registry registry of the properties of the context.
     */
    @DynamicPropertySource
    static void x509(final DynamicPropertyRegistry registry) {
        registry.add("authserver.x509.enabled", () -> "true");
        registry.add("authserver.x509.forwarded-header", () -> HEADER);
        registry.add("authserver.x509.trusted-proxies", () -> "127.0.0.1");
    }

    /**
     * Generates the certificate.
     */
    @BeforeEach
    void generateCertificate() {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
        certificate = TestCertificates.generate("user-" + UUID.randomUUID());
    }

    /**
     * Verifies that a bound certificate signs the account in, resumes the authorization request and is reported as
     * {@code sc} in the tokens.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheCertificateIsBound_signsInAndTheTokensReportSc() throws Exception {
        final var user = fixtures.createUser();
        bind(user.username());
        final var client = fixtures.createCodeClient();
        final var verifier = AuthServerFixtures.randomValue() + AuthServerFixtures.randomValue();
        final var authorizeUri = AuthServerFixtures.authorizeUri(client, verifier, Map.of());
        final var session = new MockHttpSession();
        mockMvc.perform(get(authorizeUri).session(session)).andExpect(status().is3xxRedirection());

        final var resumed = mockMvc.perform(signIn().session(session).header(HEADER, encoded()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, containsString("/oauth2/authorize?"))).andReturn()
                .getResponse().getRedirectedUrl();
        assertNotNull(resumed);
        final var authorized = mockMvc.perform(get(URI.create(resumed)).session(session))
                .andExpect(status().is3xxRedirection()).andReturn();
        final var tokens = fixtures.exchangeCode(client, AuthServerFixtures.codeOf(authorized), verifier);

        final var claims = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(List.of("sc"), claims.get("amr").valueStream().map(node -> node.asString()).toList());
        mockMvc.perform(get(PROTECTED_PAGE).session(session)).andExpect(status().isOk());
    }

    /**
     * Verifies that a certificate that is bound to nobody is sent back to the login page, signed in as nobody.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheCertificateIsNotBound_redirectsToTheLoginPage() throws Exception {
        final var session = new MockHttpSession();

        mockMvc.perform(signIn().session(session).header(HEADER, encoded()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith(FAILED)));

        assertNotSignedIn(session);
    }

    /**
     * Verifies that a request without a certificate is sent back to the login page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenNoCertificateIsPresented_redirectsToTheLoginPage() throws Exception {
        mockMvc.perform(signIn())
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith(FAILED)));
    }

    /**
     * Verifies that a header sent by anybody but the proxy is ignored, even when it carries a bound certificate: the
     * header cannot be used to pose as the owner of a certificate.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheHeaderComesFromAnUntrustedAddress_isRefused() throws Exception {
        final var user = fixtures.createUser();
        bind(user.username());
        final var session = new MockHttpSession();

        mockMvc.perform(signIn().session(session).header(HEADER, encoded())
                        .with(request -> {
                            request.setRemoteAddr(UNTRUSTED);
                            return request;
                        }))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith(FAILED)));

        assertNotSignedIn(session);
    }

    /**
     * Verifies that a certificate that expired is refused even though it is bound: the proxy is not the only check,
     * so a certificate that is past its validity never signs an account in.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheBoundCertificateHasExpired_isRefused() throws Exception {
        final var user = fixtures.createUser();
        certificate = TestCertificates.generateExpired("expired-" + UUID.randomUUID());
        bind(user.username());
        final var session = new MockHttpSession();

        mockMvc.perform(signIn().session(session).header(HEADER, encoded()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith(FAILED)));

        assertNotSignedIn(session);
    }

    /**
     * Verifies that a certificate whose binding was removed is refused from then on, while it signed the account in
     * before.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheBindingWasRemoved_isRefused() throws Exception {
        final var user = fixtures.createUser();
        final var binding = bind(user.username());
        mockMvc.perform(signIn().header(HEADER, encoded()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, not(endsWith(FAILED))));
        unbindCertificateUseCase.execute(binding.userId(), user.username(), binding.id());
        final var session = new MockHttpSession();

        mockMvc.perform(signIn().session(session).header(HEADER, encoded()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith(FAILED)));

        assertNotSignedIn(session);
    }

    /**
     * Verifies that a certificate issued by a certificate authority, the kind a proxy forwards, signs the account it
     * is bound to in.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheCertificateIsIssuedByAnAuthority_signsTheBoundAccountIn() throws Exception {
        try (var pki = TestPki.create("authority-" + UUID.randomUUID())) {
            final var user = fixtures.createUser();
            certificate = pki.issueClient("issued-" + UUID.randomUUID()).certificate();
            bind(user.username());
            final var session = new MockHttpSession();

            mockMvc.perform(signIn().session(session).header(HEADER, encoded()))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(header().string(LOCATION, not(endsWith(FAILED))));

            assertEquals(user.username(), signedInName(session));
        }
    }

    /**
     * Verifies that a disabled account cannot sign in with its certificate.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheAccountIsDisabled_isRefused() throws Exception {
        final var username = "disabled-" + UUID.randomUUID();
        final var account = new UserAccount(UUID.randomUUID(), username,
                passwordEncoder.encode(AuthServerFixtures.randomValue()), false, List.of("ROLE_USER"),
                username + "@example.com", true, AuthServerFixtures.TENANT);
        userAccounts.save(account);
        bindCertificateUseCase.execute(account.id(), username, certificate.fingerprintSha256(), "CN=disabled");
        final var session = new MockHttpSession();

        mockMvc.perform(signIn().session(session).header(HEADER, encoded()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith(FAILED)));

        assertNotSignedIn(session);
    }

    /**
     * Verifies that a {@code GET} of the sign-in path, even with a bound certificate, signs nobody in: it is not a
     * sign-in request, so it ends with the chain's catch-all rule and goes to the login page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenRequestedWithGet_signsNobodyIn() throws Exception {
        final var user = fixtures.createUser();
        bind(user.username());
        final var session = new MockHttpSession();

        mockMvc.perform(get(X509_LOGIN).session(session).header(HEADER, encoded()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith("/login")));

        assertNotSignedIn(session);
    }

    /**
     * Verifies that a post without the CSRF token, even with a bound certificate, is refused before the certificate is
     * looked at, so a cross-site page cannot make a browser sign in with its certificate.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void x509Login_whenTheCsrfTokenIsMissing_isRefused() throws Exception {
        final var user = fixtures.createUser();
        bind(user.username());
        final var session = new MockHttpSession();

        final var status = mockMvc.perform(post(X509_LOGIN).session(session).header(HEADER, encoded()))
                .andReturn().getResponse().getStatus();

        assertEquals(FORBIDDEN, status);
        assertNotSignedIn(session);
    }

    /**
     * Verifies that the login page offers the certificate sign-in as a form that posts to the relative path (a proxy
     * forwards the certificate) with the CSRF token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void loginPage_whenTheSignInWithACertificateIsOn_offersAFormThatPostsWithTheCsrfToken() throws Exception {
        final var page = mockMvc.perform(get("/login")).andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString();

        final var form = X509_FORM.matcher(page);
        assertTrue(form.find(), "The login page must offer the certificate sign-in");
        assertTrue(form.group(1).contains("action=\"" + X509_LOGIN + "\""), form.group(1));
        assertTrue(form.group(1).contains("method=\"post\""), form.group(1));
        assertTrue(form.group(2).contains("name=\"_csrf\""), form.group(2));
    }

    /**
     * Verifies that the pages of an ordinary visitor are not affected: a protected page still redirects to the login
     * page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedPage_whenNobodyIsSignedIn_stillRedirectsToTheLoginPage() throws Exception {
        mockMvc.perform(get(PROTECTED_PAGE))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith("/login")));
    }

    /**
     * Binds the certificate to an account.
     *
     * @param username name of the account.
     * @return the binding.
     */
    private CertificateBinding bind(final String username) {
        final var account = userAccounts.findByUsername(username).orElseThrow();
        return bindCertificateUseCase.execute(account.id(), username, certificate.fingerprintSha256(), "CN=test");
    }

    /**
     * Builds the sign-in request the form of the login page sends: a post with the CSRF token.
     *
     * @return the request.
     */
    private static MockHttpServletRequestBuilder signIn() {
        return post(X509_LOGIN).with(csrf());
    }

    /**
     * Encodes the certificate the way a proxy forwards it.
     *
     * @return the URL-encoded PEM.
     */
    private String encoded() {
        return UriUtils.encode(certificate.pem(), StandardCharsets.UTF_8);
    }

    /**
     * Reads the name of the user a session is signed in as.
     *
     * @param session the session.
     * @return the user name, or {@code null} when nobody is signed in.
     */
    private static String signedInName(final MockHttpSession session) {
        final var context = (SecurityContext) session.getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        return context == null || context.getAuthentication() == null ? null : context.getAuthentication().getName();
    }

    /**
     * Checks that the session holds no sign-in, by asking for a page that needs one.
     *
     * @param session the session.
     * @throws Exception if the request cannot be performed.
     */
    private void assertNotSignedIn(final MockHttpSession session) throws Exception {
        mockMvc.perform(get(PROTECTED_PAGE).session(session)).andExpect(status().is3xxRedirection());
    }
}
