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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.irurueta.authserver.testsupport.TestCertificates;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link AnyClientCertificateTrustManager}, with a certificate generated at run time.
 */
class AnyClientCertificateTrustManagerTest {

    /** Authentication type of a client certificate. */
    private static final String AUTH_TYPE = "ECDSA";

    /** Trust manager under test. */
    private final AnyClientCertificateTrustManager trustManager = new AnyClientCertificateTrustManager();

    /**
     * Verifies that a client certificate chain is accepted, whatever authority issued it.
     */
    @Test
    void checkClientTrusted_whenAChainIsPresented_acceptsIt() {
        final var certificate = TestCertificates.generate("trust-manager-test").certificate();

        assertDoesNotThrow(() -> trustManager.checkClientTrusted(new X509Certificate[] {certificate}, AUTH_TYPE));
    }

    /**
     * Verifies that it never vouches for a server.
     */
    @Test
    void checkServerTrusted_whenAChainIsPresented_isRefused() {
        final var certificate = TestCertificates.generate("trust-manager-test").certificate();

        assertThrows(CertificateException.class,
                () -> trustManager.checkServerTrusted(new X509Certificate[] {certificate}, AUTH_TYPE));
    }

    /**
     * Verifies that no authority is advertised, and that the array handed out is a copy.
     */
    @Test
    void getAcceptedIssuers_whenAsked_returnsNoneAndACopy() {
        assertEquals(0, trustManager.getAcceptedIssuers().length);
        assertNotSame(trustManager.getAcceptedIssuers(), trustManager.getAcceptedIssuers());
    }
}
