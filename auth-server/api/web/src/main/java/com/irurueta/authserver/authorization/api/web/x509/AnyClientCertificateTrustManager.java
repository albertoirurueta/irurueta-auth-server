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
package com.irurueta.authserver.authorization.api.web.x509;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

/**
 * The trust manager of the dedicated TLS port: it accepts any client certificate and advertises no certificate
 * authority. The port requests a certificate without validating it against an authority ({@code optionalNoCA}); what
 * identifies the client is the SHA-256 fingerprint of the certificate, which has to be bound to an account, and what
 * the application checks is that the certificate is within its validity ({@link CertificatePrincipalExtractor}). The
 * empty list of accepted issuers matters: with the default trust manager the server lists the authorities of the JVM's
 * default trust store, and a client presents only a certificate issued by a listed authority. Tomcat creates the class
 * by name, so it is public with a public constructor and no state.
 */
public class AnyClientCertificateTrustManager implements X509TrustManager {

    /** No authority is advertised, so the client may present any certificate it holds. */
    private static final X509Certificate[] NO_ISSUERS = new X509Certificate[0];

    /**
     * Accepts the certificate chain of a client: the binding of its fingerprint decides.
     *
     * @param chain    the chain of the client.
     * @param authType the authentication type.
     */
    @Override
    public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
        // deliberately nothing: see the class comment
    }

    /**
     * Refuses to vouch for a server: this manager is only ever used by the server side of the connector.
     *
     * @param chain    the chain of the server.
     * @param authType the authentication type.
     * @throws CertificateException always.
     */
    @Override
    public void checkServerTrusted(final X509Certificate[] chain, final String authType)
            throws CertificateException {
        throw new CertificateException("This trust manager does not validate server certificates");
    }

    /**
     * Advertises no certificate authority.
     *
     * @return an empty array.
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return NO_ISSUERS.clone();
    }
}
