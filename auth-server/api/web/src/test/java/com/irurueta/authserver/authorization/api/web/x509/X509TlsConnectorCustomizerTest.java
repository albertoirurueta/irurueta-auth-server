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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;

/**
 * Unit tests of {@link X509TlsConnectorCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class X509TlsConnectorCustomizerTest {

    /** Port of the dedicated connector. */
    private static final int PORT = 8443;

    /** Finds the key store. */
    @Mock
    private X509TlsKeyStoreResolver keyStoreResolver;

    /**
     * Verifies that the connector is a secure one that requests a certificate without validating it against a CA, with
     * the server certificate of the key store.
     */
    @Test
    void connector_whenBuilt_requestsACertificateWithoutValidatingItAgainstACa() {
        final var password = UUID.randomUUID().toString();
        final var keyStore = new X509TlsKeyStore(Path.of("server.p12"), password, "PKCS12");

        final var connector = customizer(PORT).connector(keyStore);

        assertEquals(PORT, connector.getPort());
        assertEquals("https", connector.getScheme());
        assertTrue(connector.getSecure());
        final var protocol = (AbstractHttp11Protocol<?>) connector.getProtocolHandler();
        assertTrue(protocol.isSSLEnabled());
        final var host = protocol.findSslHostConfigs()[0];
        assertEquals(SSLHostConfig.CertificateVerification.OPTIONAL_NO_CA, host.getCertificateVerification());
        final var certificate = host.getCertificates().iterator().next();
        assertEquals("server.p12", certificate.getCertificateKeystoreFile());
        assertEquals(password, certificate.getCertificateKeystorePassword());
        assertEquals("PKCS12", certificate.getCertificateKeystoreType());
        assertEquals(AnyClientCertificateTrustManager.class.getName(), host.getTrustManagerClassName());
    }

    /**
     * Verifies that a port adds the connector to the server.
     */
    @Test
    void customize_whenAPortIsConfigured_addsTheConnector() {
        final var factory = mock(TomcatServletWebServerFactory.class);
        when(keyStoreResolver.resolve())
                .thenReturn(new X509TlsKeyStore(Path.of("server.p12"), UUID.randomUUID().toString(), "PKCS12"));

        customizer(PORT).customize(factory);

        final var captor = ArgumentCaptor.<Connector>captor();
        verify(factory).addAdditionalConnectors(captor.capture());
        assertEquals(PORT, captor.getValue().getPort());
    }

    /**
     * Verifies that without a port nothing is added and no key store is looked for.
     */
    @Test
    void customize_whenNoPortIsConfigured_doesNothing() {
        final var factory = mock(TomcatServletWebServerFactory.class);

        customizer(0).customize(factory);

        verify(factory, never()).addAdditionalConnectors(any());
        verifyNoInteractions(keyStoreResolver);
    }

    /**
     * Builds the customizer.
     *
     * @param port the TLS port, {@code 0} for none.
     * @return the customizer.
     */
    private X509TlsConnectorCustomizer customizer(final int port) {
        return new X509TlsConnectorCustomizer(
                new X509Properties(true, "", List.of(), port, "sc", "", "", "PKCS12"), keyStoreResolver);
    }
}
