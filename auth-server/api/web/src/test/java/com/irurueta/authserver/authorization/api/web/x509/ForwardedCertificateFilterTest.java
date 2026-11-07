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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.irurueta.authserver.testsupport.TestCertificates;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.util.UriUtils;

/**
 * Unit tests of {@link ForwardedCertificateFilter}: a certificate is read only from a trusted proxy, so a client cannot
 * pose as anybody by sending the header itself.
 */
class ForwardedCertificateFilterTest {

    /** Name of the header. */
    private static final String HEADER = "X-Client-Cert";

    /** Range of the trusted proxies. */
    private static final String TRUSTED_RANGE = "192.0.2.0/24";

    /** An address of a trusted proxy. */
    private static final String TRUSTED = "192.0.2.10";

    /** An address nobody trusts. */
    private static final String UNTRUSTED = "198.51.100.7";

    /** Name of the attribute the certificate is left in. */
    private static final String ATTRIBUTE = ForwardedCertificateFilter.CERTIFICATE_ATTRIBUTE;

    /** A certificate generated for the run. */
    private static TestCertificates.GeneratedCertificate certificate;

    /** Filter under test. */
    private final ForwardedCertificateFilter filter = new ForwardedCertificateFilter(
            new X509Properties(true, HEADER, List.of(TRUSTED_RANGE), 0, "sc", "", "", "PKCS12"));

    /**
     * Generates the certificate.
     */
    @BeforeAll
    static void generateCertificate() {
        certificate = TestCertificates.generate("forwarded-test");
    }

    /**
     * Verifies that the URL-encoded PEM a proxy forwards, as nginx does, is read.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenTrustedProxyForwardsEncodedPem_setsTheCertificate() throws Exception {
        final var request = request(TRUSTED, UriUtils.encode(certificate.pem(), StandardCharsets.UTF_8));

        filter(request);

        assertEquals(certificate.fingerprintSha256(), fingerprintOf(request));
    }

    /**
     * Verifies that a PEM that was not encoded is read too.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenTrustedProxyForwardsPlainPem_setsTheCertificate() throws Exception {
        final var request = request(TRUSTED, certificate.pem().replace("\n", " "));

        filter(request);

        assertEquals(certificate.fingerprintSha256(), fingerprintOf(request));
    }

    /**
     * Verifies that the base64 of the DER form is read too.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenTrustedProxyForwardsBase64Der_setsTheCertificate() throws Exception {
        final var request = request(TRUSTED,
                Base64.getEncoder().encodeToString(certificate.certificate().getEncoded()));

        filter(request);

        assertEquals(certificate.fingerprintSha256(), fingerprintOf(request));
    }

    /**
     * Verifies that a header from an address that is not a trusted proxy is ignored: nobody may pose as the owner of a
     * certificate.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenRequestIsNotFromATrustedProxy_refusesTheHeader() throws Exception {
        final var request = request(UNTRUSTED, UriUtils.encode(certificate.pem(), StandardCharsets.UTF_8));

        final var chain = filter(request);

        assertNull(request.getAttribute(ATTRIBUTE));
        assertNotNull(chain.getRequest(), "the request still goes on, unauthenticated");
    }

    /**
     * Verifies that a request without a known address is not trusted.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenTheAddressIsUnknown_refusesTheHeader() throws Exception {
        final var request = request(TRUSTED, UriUtils.encode(certificate.pem(), StandardCharsets.UTF_8));
        request.setRemoteAddr("");

        filter(request);

        assertNull(request.getAttribute(ATTRIBUTE));
    }

    /**
     * Verifies that the header is only read on the sign-in path.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenPathIsNotTheSignIn_ignoresTheHeader() throws Exception {
        final var request = request(TRUSTED, UriUtils.encode(certificate.pem(), StandardCharsets.UTF_8));
        request.setRequestURI("/login");
        request.setServletPath("/login");

        filter(request);

        assertNull(request.getAttribute(ATTRIBUTE));
    }

    /**
     * Verifies that the header is not read on a {@code GET} of the sign-in path, which never signs anybody in.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenTheSignInPathIsReadWithGet_ignoresTheHeader() throws Exception {
        final var request = request(TRUSTED, UriUtils.encode(certificate.pem(), StandardCharsets.UTF_8));
        request.setMethod("GET");

        filter(request);

        assertNull(request.getAttribute(ATTRIBUTE));
    }

    /**
     * Verifies that a request without the header goes on untouched.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenThereIsNoHeader_leavesTheRequestAlone() throws Exception {
        final var request = request(TRUSTED, null);

        final var chain = filter(request);

        assertNull(request.getAttribute(ATTRIBUTE));
        assertNotNull(chain.getRequest());
    }

    /**
     * Verifies that a value that is not a certificate is ignored.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenTheValueIsNotACertificate_ignoresIt() throws Exception {
        final var request = request(TRUSTED, Base64.getEncoder().encodeToString("not a certificate".getBytes(
                StandardCharsets.US_ASCII)));

        filter(request);

        assertNull(request.getAttribute(ATTRIBUTE));
    }

    /**
     * Verifies that a value that is not base64 is ignored.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenTheValueIsNotBase64_ignoresIt() throws Exception {
        filter(request(TRUSTED, "%%%"));
        final var request = request(TRUSTED, "!!!");

        filter(request);

        assertNull(request.getAttribute(ATTRIBUTE));
    }

    /**
     * Verifies that a value that is too long is not even parsed.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenTheValueIsTooLong_ignoresIt() throws Exception {
        final var request = request(TRUSTED, "A".repeat(ForwardedCertificateFilter.MAX_HEADER_LENGTH + 1));

        filter(request);

        assertNull(request.getAttribute(ATTRIBUTE));
    }

    /**
     * Runs the filter.
     *
     * @param request the request.
     * @return the chain the filter continued.
     * @throws Exception if the filter fails.
     */
    private MockFilterChain filter(final MockHttpServletRequest request) throws Exception {
        final var chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        return chain;
    }

    /**
     * Builds a sign-in request.
     *
     * @param address address of the caller.
     * @param header  value of the header, or {@code null} for none.
     * @return the request.
     */
    private static MockHttpServletRequest request(final String address, final String header) {
        final var request = new MockHttpServletRequest("POST", "/login/x509");
        request.setRemoteAddr(address);
        if (header != null) {
            request.addHeader(HEADER, header);
        }
        return request;
    }

    /**
     * Computes the fingerprint of the certificate left in the request.
     *
     * @param request the request.
     * @return the fingerprint.
     * @throws CertificateEncodingException if the certificate cannot be encoded.
     */
    private static String fingerprintOf(final MockHttpServletRequest request) throws CertificateEncodingException {
        final var certificates = (X509Certificate[]) request.getAttribute(ATTRIBUTE);
        assertNotNull(certificates);
        return TestCertificates.of(certificates[0]).fingerprintSha256();
    }
}
