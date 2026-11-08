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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Arrays;
import java.util.function.Consumer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.util.StringUtils;

// tag::clientauth-certificate-verifier[]
/**
 * Verifies the certificate a client presented on the TLS port (RFC 8705), replacing the framework's verifier, which
 * has no trust anchors of its own.
 * <ul>
 * <li>{@code tls_client_auth}: the chain must validate (PKIX path validation) against the configured trust anchors,
 * and the subject DN of the leaf must equal the one registered for the client. Revocation checking is disabled: it
 * needs a CRL or OCSP endpoint reachable from the server, which this example does not assume. No configured anchor
 * means no client is accepted.</li>
 * <li>{@code self_signed_tls_client_auth}: the certificate must be self-signed and its public key one of the keys of
 * the client's registered JWK set; otherwise the decision is the framework's own (which compares it with the keys of
 * the client's {@code jwkSetUrl}), whose provider is {@code defaultProvider}.</li>
 * </ul>
 * Every refusal is {@code invalid_client}.
 */
@RequiredArgsConstructor
public class ClientCertificateVerifier implements Consumer<OAuth2ClientAuthenticationContext> {

    /** Type of the certification path. */
    private static final String CERTIFICATE_TYPE = "X.509";

    /** Algorithm of the path validation. */
    private static final String PKIX = "PKIX";

    /** The trusted certificate authorities. */
    private final MtlsTrustAnchors trustAnchors;

    /** A default-configured provider of the framework, asked about a self-signed certificate with no registered key. */
    private final AuthenticationProvider defaultProvider;

    /**
     * Verifies the certificate of the client.
     *
     * @param context the client and its authentication.
     * @throws OAuth2AuthenticationException {@code invalid_client} if the certificate is not accepted.
     */
    @Override
    public void accept(final OAuth2ClientAuthenticationContext context) {
        final OAuth2ClientAuthenticationToken authentication = context.getAuthentication();
        final var method = authentication.getClientAuthenticationMethod();
        final var chain = chainOf(authentication);
        if (ClientAuthenticationMethod.TLS_CLIENT_AUTH.equals(method)) {
            verifyCaIssued(context, chain);
        } else if (ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.equals(method)) {
            verifySelfSigned(context, authentication, chain);
        } else {
            throw invalidClient();
        }
    }

    /**
     * Verifies a certificate issued by a trusted authority.
     *
     * @param context the client and its authentication.
     * @param chain   the presented chain, the leaf first.
     */
    private void verifyCaIssued(final OAuth2ClientAuthenticationContext context, final X509Certificate[] chain) {
        if (trustAnchors.anchors().isEmpty()) {
            throw invalidClient();
        }
        final var leaf = chain[0];
        // the leaf is the certificate whose key the TLS handshake proved and whose DN is compared below: it must be
        // the first certificate of the validated path, never an anchor left out of it
        if (isAnchor(leaf)) {
            throw invalidClient();
        }
        final var path = Arrays.stream(chain).filter(certificate -> !isAnchor(certificate)).toList();
        try {
            final var parameters = new PKIXParameters(trustAnchors.anchors());
            parameters.setRevocationEnabled(false);
            CertPathValidator.getInstance(PKIX).validate(
                    CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertPath(path), parameters);
        } catch (GeneralSecurityException e) {
            throw invalidClient();
        }
        final var expected = context.getRegisteredClient().getClientSettings().getX509CertificateSubjectDN();
        if (!StringUtils.hasText(expected) || !expected.equals(leaf.getSubjectX500Principal().getName())) {
            throw invalidClient();
        }
    }

    /**
     * Verifies a self-signed certificate.
     *
     * @param context        the client and its authentication.
     * @param authentication the client authentication.
     * @param chain          the presented chain, the leaf first.
     */
    private void verifySelfSigned(final OAuth2ClientAuthenticationContext context,
                                  final OAuth2ClientAuthenticationToken authentication,
                                  final X509Certificate[] chain) {
        final var leaf = chain[0];
        if (leaf.getIssuerX500Principal().equals(leaf.getSubjectX500Principal())
                && matchesRegisteredKey(context, leaf.getPublicKey())) {
            return;
        }
        // the result is not needed: the provider throws invalid_client when the certificate does not match
        defaultProvider.authenticate(authentication);
    }

    /**
     * Tells whether a key is one of the registered JWK set of the client.
     *
     * @param context the client and its authentication.
     * @param key     the public key of the certificate.
     * @return {@code true} when a registered key equals it.
     */
    private boolean matchesRegisteredKey(final OAuth2ClientAuthenticationContext context, final PublicKey key) {
        final var jwks = context.getRegisteredClient().getClientSettings()
                .<Object>getSetting(RegisteredJwksClientAssertionDecoderFactory.JWKS_SETTING);
        if (!(jwks instanceof String json) || !StringUtils.hasText(json)) {
            return false;
        }
        try {
            for (final JWK jwk : JWKSet.parse(json).getKeys()) {
                if (jwk instanceof AsymmetricJWK asymmetric && Arrays.equals(asymmetric.toPublicKey().getEncoded(),
                        key.getEncoded())) {
                    return true;
                }
            }
            return false;
        } catch (ParseException | JOSEException e) {
            return false;
        }
    }

    /**
     * Tells whether a certificate is itself a trust anchor, which a certification path must not contain.
     *
     * @param certificate the certificate.
     * @return {@code true} when an anchor holds exactly that certificate.
     */
    private boolean isAnchor(final X509Certificate certificate) {
        return trustAnchors.anchors().stream().anyMatch(anchor -> certificate.equals(anchor.getTrustedCert()));
    }

    /**
     * Reads the presented chain.
     *
     * @param authentication the client authentication.
     * @return the chain, the leaf first.
     */
    private static X509Certificate[] chainOf(final Authentication authentication) {
        if (authentication.getCredentials() instanceof X509Certificate[] chain && chain.length > 0) {
            return chain;
        }
        throw invalidClient();
    }

    /**
     * Builds the refusal.
     *
     * @return the {@code invalid_client} exception.
     */
    private static OAuth2AuthenticationException invalidClient() {
        return new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
    }
}
// end::clientauth-certificate-verifier[]
