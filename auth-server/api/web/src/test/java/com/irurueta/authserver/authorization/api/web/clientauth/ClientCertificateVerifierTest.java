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
package com.irurueta.authserver.authorization.api.web.clientauth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.testsupport.TestCertificates;
import com.irurueta.authserver.testsupport.TestPki;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.nio.file.Path;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

/**
 * Unit tests of {@link ClientCertificateVerifier}. The authority and every certificate are generated at run time.
 */
@ExtendWith(MockitoExtension.class)
class ClientCertificateVerifierTest {

    /** Name of the client the certificates are issued to. */
    private static final String CLIENT_NAME = "mtls-client";

    /** The certificate authority of the test. */
    private static TestPki pki;

    /** The trust anchors holding the authority. */
    private static MtlsTrustAnchors anchors;

    /** A certificate issued by the authority to the client. */
    private static X509Certificate issued;

    /** Subject DN of the issued certificate, as the framework compares it. */
    private static String issuedDn;

    /** The framework's provider that decides about self-signed certificates with no registered key. */
    @Mock
    private AuthenticationProvider defaultProvider;

    /** Verifier under test, trusting the authority. */
    private ClientCertificateVerifier verifier;

    /**
     * Creates the authority and a client certificate.
     */
    @BeforeAll
    static void createAuthority() {
        pki = TestPki.create("verifier-authority-" + UUID.randomUUID());
        final var identity = pki.issueClient(CLIENT_NAME);
        issued = identity.certificate().certificate();
        issuedDn = issued.getSubjectX500Principal().getName();
        anchors = new TrustAnchorsReader().read(List.of(authorityPem(identity).toString()));
    }

    /**
     * Removes the generated files.
     */
    @AfterAll
    static void removeAuthority() {
        pki.close();
    }

    /** A certificate of the authority with the registered DN is accepted. */
    @Test
    void accept_whenTlsClientAuthCertificateIsIssuedByATrustedAuthority_doesNotThrow() {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);

        assertDoesNotThrow(() -> verifier.accept(context(ClientAuthenticationMethod.TLS_CLIENT_AUTH,
                tlsSettings(issuedDn), issued)));
    }

    /** The chain may include the authority itself. */
    @Test
    void accept_whenChainIncludesTheAuthority_doesNotThrow() {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);
        final var authority = anchors.anchors().iterator().next().getTrustedCert();

        assertDoesNotThrow(() -> verifier.accept(context(ClientAuthenticationMethod.TLS_CLIENT_AUTH,
                tlsSettings(issuedDn), issued, authority)));
    }

    /** A certificate whose DN differs from the registered one is refused. */
    @Test
    void accept_whenSubjectDnDoesNotMatch_throwsInvalidClient() {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);
        final var context = context(ClientAuthenticationMethod.TLS_CLIENT_AUTH, tlsSettings("CN=someone-else"), issued);

        assertInvalidClient(context);
    }

    /** A client with no registered DN is refused. */
    @Test
    void accept_whenNoSubjectDnIsRegistered_throwsInvalidClient() {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);
        final var context = context(ClientAuthenticationMethod.TLS_CLIENT_AUTH, ClientSettings.builder().build(),
                issued);

        assertInvalidClient(context);
    }

    /** A self-issued certificate with the same DN is not accepted as CA-issued. */
    @Test
    void accept_whenCertificateIsSelfIssuedWithTheSameDn_throwsInvalidClient() {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);
        final var selfIssued = TestCertificates.generate(CLIENT_NAME).certificate();
        final var context = context(ClientAuthenticationMethod.TLS_CLIENT_AUTH,
                tlsSettings(selfIssued.getSubjectX500Principal().getName()), selfIssued);

        assertInvalidClient(context);
    }

    /** An expired certificate of the authority is refused. */
    @Test
    void accept_whenCertificateExpired_throwsInvalidClient() {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);
        final var expired = pki.issueExpiredClient(CLIENT_NAME).certificate().certificate();
        final var context = context(ClientAuthenticationMethod.TLS_CLIENT_AUTH,
                tlsSettings(expired.getSubjectX500Principal().getName()), expired);

        assertInvalidClient(context);
    }

    /** With no trusted authority no CA-issued certificate is accepted. */
    @Test
    void accept_whenNoAuthorityIsConfigured_throwsInvalidClient() {
        verifier = new ClientCertificateVerifier(new MtlsTrustAnchors(Set.of()), defaultProvider);

        assertInvalidClient(context(ClientAuthenticationMethod.TLS_CLIENT_AUTH, tlsSettings(issuedDn), issued));
    }

    /** A chain made only of an authority certificate leaves nothing to validate and is refused. */
    @Test
    void accept_whenChainIsOnlyTheAuthority_throwsInvalidClient() {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);
        final var authority = anchors.anchors().iterator().next().getTrustedCert();

        assertInvalidClient(context(ClientAuthenticationMethod.TLS_CLIENT_AUTH,
                tlsSettings(authority.getSubjectX500Principal().getName()), authority));
    }

    /** Credentials that are not a certificate chain are refused. */
    @Test
    void accept_whenCredentialsAreNotACertificateChain_throwsInvalidClient() {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);
        final var token = new OAuth2ClientAuthenticationToken(client(tlsSettings(issuedDn)),
                ClientAuthenticationMethod.TLS_CLIENT_AUTH, "secret");

        assertInvalidClient(OAuth2ClientAuthenticationContext.with(token)
                .registeredClient(client(tlsSettings(issuedDn))).build());
    }

    /** Any other method is refused. */
    @Test
    void accept_whenMethodIsNotMutualTls_throwsInvalidClient() {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);

        assertInvalidClient(context(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, tlsSettings(issuedDn), issued));
    }

    /** A self-signed certificate whose key is registered is accepted without asking the framework. */
    @Test
    void accept_whenSelfSignedKeyIsRegistered_doesNotThrowAndDoesNotAskTheFramework() throws Exception {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);
        final var certificate = TestCertificates.generate(CLIENT_NAME).certificate();

        assertDoesNotThrow(() -> verifier.accept(context(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
                jwksSettings(certificate), certificate)));
        verify(defaultProvider, never()).authenticate(any());
    }

    /** A self-signed certificate with no registered keys is left to the framework's provider. */
    @Test
    void accept_whenNoJwksIsRegistered_delegatesToTheFrameworkProvider() {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);
        final var certificate = TestCertificates.generate(CLIENT_NAME).certificate();
        final var context = context(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
                ClientSettings.builder().build(), certificate);

        assertDoesNotThrow(() -> verifier.accept(context));

        verify(defaultProvider).authenticate(context.getAuthentication());
    }

    /** A self-signed certificate whose key is not the registered one is left to the framework, which can refuse it. */
    @Test
    void accept_whenKeyIsNotTheRegisteredOne_propagatesTheFrameworkRefusal() throws Exception {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);
        final var presented = TestCertificates.generate(CLIENT_NAME).certificate();
        final var registered = TestCertificates.generate(CLIENT_NAME).certificate();
        final var refusal = new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        when(defaultProvider.authenticate(any())).thenThrow(refusal);
        final var context = context(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH, jwksSettings(registered),
                presented);

        assertSame(refusal, assertThrows(OAuth2AuthenticationException.class, () -> verifier.accept(context)));
    }

    /** A certificate that is not self-signed is never matched against the registered keys. */
    @Test
    void accept_whenCertificateIsNotSelfSigned_delegatesEvenIfItsKeyIsRegistered() throws Exception {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);

        verifier.accept(context(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH, jwksSettings(issued), issued));

        verify(defaultProvider).authenticate(any());
    }

    /** Stored keys that cannot be read do not match, so the framework decides. */
    @Test
    void accept_whenStoredJwksIsNotAJwkSet_delegatesToTheFrameworkProvider() {
        verifier = new ClientCertificateVerifier(anchors, defaultProvider);
        final var certificate = TestCertificates.generate(CLIENT_NAME).certificate();
        final var settings = ClientSettings.builder()
                .setting(RegisteredJwksClientAssertionDecoderFactory.JWKS_SETTING, "not json").build();

        verifier.accept(context(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH, settings, certificate));

        verify(defaultProvider).authenticate(any());
    }

    /**
     * Checks that a context is refused with invalid_client.
     *
     * @param context the context.
     */
    private void assertInvalidClient(final OAuth2ClientAuthenticationContext context) {
        final var error = assertThrows(OAuth2AuthenticationException.class, () -> verifier.accept(context));

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, error.getError().getErrorCode());
    }

    /**
     * Builds the settings of a client authenticated by a CA-issued certificate.
     *
     * @param subjectDn the registered subject DN.
     * @return the settings.
     */
    private static ClientSettings tlsSettings(final String subjectDn) {
        return ClientSettings.builder().x509CertificateSubjectDN(subjectDn).build();
    }

    /**
     * Builds the settings of a client with the certificate's key registered as its JWK set.
     *
     * @param certificate the certificate whose key is registered.
     * @return the settings.
     * @throws JOSEException if the key cannot be converted.
     */
    private static ClientSettings jwksSettings(final X509Certificate certificate) throws JOSEException {
        return ClientSettings.builder().setting(RegisteredJwksClientAssertionDecoderFactory.JWKS_SETTING,
                new JWKSet(jwkOf(certificate)).toString()).build();
    }

    /**
     * Converts the public key of a certificate to a JWK.
     *
     * @param certificate the certificate.
     * @return the public JWK.
     * @throws JOSEException if the key is neither an RSA nor an EC key.
     */
    private static JWK jwkOf(final X509Certificate certificate) throws JOSEException {
        final var key = certificate.getPublicKey();
        if (key instanceof RSAPublicKey rsa) {
            return new RSAKey.Builder(rsa).build();
        }
        if (key instanceof ECPublicKey ec) {
            return new ECKey.Builder(Curve.forECParameterSpec(ec.getParams()), ec).build();
        }
        throw new JOSEException("Unsupported key type " + key.getAlgorithm());
    }

    /**
     * Builds the authentication context of a client presenting a chain.
     *
     * @param method the authentication method.
     * @param settings the client's settings.
     * @param chain  the presented certificates, the leaf first.
     * @return the context.
     */
    private static OAuth2ClientAuthenticationContext context(final ClientAuthenticationMethod method,
            final ClientSettings settings, final X509Certificate... chain) {
        final var registered = client(settings);
        return OAuth2ClientAuthenticationContext
                .with(new OAuth2ClientAuthenticationToken(registered, method, chain))
                .registeredClient(registered).build();
    }

    /**
     * Builds a client.
     *
     * @param settings the client's settings.
     * @return the client.
     */
    private static RegisteredClient client(final ClientSettings settings) {
        return RegisteredClient.withId("id-1").clientId(CLIENT_NAME)
                .clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).clientSettings(settings).build();
    }

    /**
     * Finds the PEM file of the authority next to the identity's key store.
     *
     * @param identity an identity issued by the authority.
     * @return the file.
     */
    private static Path authorityPem(final TestPki.Identity identity) {
        return identity.keyStore().getParent().resolve("ca.pem");
    }
}
