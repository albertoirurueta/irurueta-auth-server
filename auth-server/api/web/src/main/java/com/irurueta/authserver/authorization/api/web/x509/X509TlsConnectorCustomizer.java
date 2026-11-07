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

import lombok.RequiredArgsConstructor;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;

// tag::x509-tls-connector[]
/**
 * Adds the dedicated TLS port that requests a client certificate, when {@code authserver.x509.port} is set. The main
 * port is left as it is, so the rest of the application never asks a browser for a certificate. The connector
 * <em>requests</em> a certificate without requiring one and without validating it against a CA
 * ({@code optionalNoCA}): the TLS handshake proves that the client holds the private key, and what identifies the
 * client is the fingerprint of the certificate, which has to be bound to an account. The servlet container leaves the
 * certificate in the request attribute that the X.509 filter reads. The connector's trust manager
 * ({@link AnyClientCertificateTrustManager}) advertises no certificate authority: without it the handshake lists the
 * authorities of the JVM's default trust store, and a client offers only a certificate issued by a listed authority,
 * so the certificate of a private authority would never be presented.
 */
@RequiredArgsConstructor
public class X509TlsConnectorCustomizer implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

    /** Value of the certificate verification that asks for a certificate but does not validate it. */
    static final String CERTIFICATE_VERIFICATION = "optionalNoCA";

    /** Scheme of the connector. */
    private static final String SCHEME = "https";

    /** Settings of the sign-in with a certificate. */
    private final X509Properties properties;

    /** Finds the key store with the server certificate. */
    private final X509TlsKeyStoreResolver keyStoreResolver;

    /**
     * Adds the connector to the server, when the port is configured.
     *
     * @param factory the factory of the embedded Tomcat.
     */
    @Override
    public void customize(final TomcatServletWebServerFactory factory) {
        if (properties.tlsEnabled()) {
            factory.addAdditionalConnectors(connector(keyStoreResolver.resolve()));
        }
    }

    /**
     * Builds the connector.
     *
     * @param keyStore the key store with the server certificate.
     * @return the connector.
     */
    Connector connector(final X509TlsKeyStore keyStore) {
        final var connector = new Connector(Http11NioProtocol.class.getName());
        connector.setScheme(SCHEME);
        connector.setSecure(true);
        connector.setPort(properties.port());
        final var protocol = (AbstractHttp11Protocol<?>) connector.getProtocolHandler();
        protocol.setSSLEnabled(true);
        final var host = new SSLHostConfig();
        host.setCertificateVerification(CERTIFICATE_VERIFICATION);
        host.setTrustManagerClassName(AnyClientCertificateTrustManager.class.getName());
        final var certificate = new SSLHostConfigCertificate(host, SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateKeystoreFile(keyStore.location().toString());
        certificate.setCertificateKeystorePassword(keyStore.password());
        certificate.setCertificateKeystoreType(keyStore.type());
        host.addCertificate(certificate);
        protocol.addSslHostConfig(host);
        return connector;
    }
}
// end::x509-tls-connector[]
