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

import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.social.GeneratedPasswordRepository;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import com.irurueta.authserver.testsupport.TestCertificates;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.json.JsonMapper;

/**
 * Checks the certificate operations of the account API as the whole application wires them: a PEM certificate is
 * bound, listed and unbound through the bearer-protected API; a certificate of another account and a value that is not
 * a certificate are refused; the last way to sign in to an account is never unbound; and, while the account has a
 * confirmed second factor, binding needs a token of a recent multi-factor sign-in. Every certificate is generated at
 * run time.
 */
class CertificateApiIT extends AbstractMfaFlow {

    /** Path of the certificates of the account API. */
    private static final String CERTIFICATES = "/api/account/certificates";

    /** The challenge of an operation that needs a recent multi-factor sign-in. */
    private static final String STEP_UP_CHALLENGE = "Bearer error=\"insufficient_user_authentication\", "
            + "acr_values=\"urn:irurueta:acr:mfa\", max_age=\"300\"";

    /** Writes the request bodies. */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** Port that stores the users. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that remembers the accounts that only hold a generated password. */
    @Autowired
    private GeneratedPasswordRepository generatedPasswords;

    /** Port that stores the bindings. */
    @Autowired
    private CertificateBindingRepository certificateBindings;


    /**
     * Verifies that a certificate is bound, listed with the fingerprint the sign-in looks up, and unbound while the
     * account keeps its password.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void certificates_whenBoundListedAndUnbound_followTheContract() throws Exception {
        final var user = getFixtures().createUser();
        final var certificate = TestCertificates.generate("bind-" + UUID.randomUUID());

        final var bound = getMockMvc().perform(bind(user.username(), certificate.pem()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.fingerprintSha256").value(certificate.fingerprintSha256()))
                .andReturn().getResponse().getContentAsString();
        final var id = AuthServerFixtures.parse(bound).get("id").asString();
        getMockMvc().perform(bind(user.username(), certificate.pem()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(id));
        getMockMvc().perform(get(CERTIFICATES).with(bearer(user.username())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].id").value(id));
        getMockMvc().perform(delete(CERTIFICATES + "/" + id).with(bearer(user.username())))
                .andExpect(status().isNoContent());

        assertEquals(0, certificateBindings.findByUser(accountId(user.username())).size());
    }

    /**
     * Verifies that a certificate bound to another account, an expired certificate and a value that is not a
     * certificate are refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void bindCertificate_whenTheCertificateCannotBeBound_isRefused() throws Exception {
        final var owner = getFixtures().createUser();
        final var other = getFixtures().createUser();
        final var certificate = TestCertificates.generate("owned-" + UUID.randomUUID());
        getMockMvc().perform(bind(owner.username(), certificate.pem())).andExpect(status().isCreated());

        getMockMvc().perform(bind(other.username(), certificate.pem()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:problem:certificate:certificate-already-bound"));
        getMockMvc().perform(bind(other.username(),
                        TestCertificates.generateExpired("expired-" + UUID.randomUUID()).pem()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:certificate:invalid-certificate"));
        getMockMvc().perform(bind(other.username(), "not a certificate"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:certificate:invalid-certificate"));
    }

    /**
     * Verifies that the only way to sign in to an account without a password of its own, its certificate, is never
     * unbound, that it can be once another certificate is bound, and that a certificate of another account is answered
     * as not found.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void unbindCertificate_whenItIsTheLastWayToSignIn_isRefused() throws Exception {
        final var user = getFixtures().createUser();
        generatedPasswords.markGenerated(accountId(user.username()));
        final var first = boundId(user.username(), TestCertificates.generate("first-" + UUID.randomUUID()).pem());

        getMockMvc().perform(delete(CERTIFICATES + "/" + first).with(bearer(user.username())))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:problem:certificate:last-sign-in-method"));
        boundId(user.username(), TestCertificates.generate("second-" + UUID.randomUUID()).pem());
        getMockMvc().perform(delete(CERTIFICATES + "/" + first).with(bearer(getFixtures().createUser().username())))
                .andExpect(status().isNotFound());
        getMockMvc().perform(delete(CERTIFICATES + "/" + first).with(bearer(user.username())))
                .andExpect(status().isNoContent());

        assertEquals(1, certificateBindings.findByUser(accountId(user.username())).size());
    }

    /**
     * Verifies that, while the account has a confirmed second factor, a token without a recent multi-factor sign-in is
     * answered with the step-up challenge and binds nothing, and a token of a recent multi-factor sign-in binds.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void bindCertificate_whenTheAccountHasASecondFactor_needsAStepUpToken() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var username = enrolled.user().username();
        final var pem = TestCertificates.generate("step-up-" + UUID.randomUUID()).pem();

        getMockMvc().perform(bind(username, pem))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", STEP_UP_CHALLENGE));
        assertEquals(0, certificateBindings.findByUser(enrolled.id()).size());
        getMockMvc().perform(post(CERTIFICATES).with(bearer(username).jwt(token -> token.subject(username)
                                .claim(ACR, AuthenticationContextClass.MULTI_FACTOR)
                                .claim(AUTH_TIME, Instant.now())))
                        .contentType(MediaType.APPLICATION_JSON).content(body(pem)))
                .andExpect(status().isCreated());

        assertEquals(1, certificateBindings.findByUser(enrolled.id()).size());
    }

    /**
     * Builds a bind request.
     *
     * @param username the account of the token.
     * @param pem      the certificate.
     * @return the request.
     */
    private static MockHttpServletRequestBuilder bind(final String username, final String pem) {
        return post(CERTIFICATES).with(bearer(username)).contentType(MediaType.APPLICATION_JSON).content(body(pem));
    }

    /**
     * Binds a certificate and answers the identifier of the binding.
     *
     * @param username the account.
     * @param pem      the certificate.
     * @return the identifier of the binding.
     * @throws Exception if the request cannot be performed.
     */
    private String boundId(final String username, final String pem) throws Exception {
        final var bound = getMockMvc().perform(bind(username, pem)).andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return AuthServerFixtures.parse(bound).get("id").asString();
    }

    /**
     * Builds the body of a bind request.
     *
     * @param pem the certificate.
     * @return the JSON body.
     */
    private static String body(final String pem) {
        return JSON.writeValueAsString(Map.of("certificate", pem));
    }

    /**
     * Builds the bearer token of an account, without any multi-factor claim.
     *
     * @param username the account.
     * @return the token.
     */
    private static JwtRequestPostProcessor bearer(final String username) {
        return jwt().jwt(token -> token.subject(username));
    }

    /**
     * Finds the identifier of an account.
     *
     * @param username the account.
     * @return its identifier.
     */
    private UUID accountId(final String username) {
        return userAccounts.findByUsername(username).orElseThrow().id();
    }
}
