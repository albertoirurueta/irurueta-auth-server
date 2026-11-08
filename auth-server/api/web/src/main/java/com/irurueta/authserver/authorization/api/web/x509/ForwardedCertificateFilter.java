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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriUtils;

// tag::x509-forwarded-filter[]
/**
 * Reads the client certificate a reverse proxy that terminates TLS forwards in a header and leaves it where the
 * servlet container leaves a certificate of its own, in the {@code jakarta.servlet.request.X509Certificate} request
 * attribute, so the same X.509 filter and principal extractor serve both transports.
 *
 * <p>A header is only ever read when the request comes from one of the configured trusted proxies: anybody else could
 * send any certificate. The address checked is {@code getRemoteAddr()}, which is the address left after Spring's or
 * Tomcat's handling of the forwarded headers; only with {@code server.forward-headers-strategy=none} is it the direct
 * network peer, because the {@code native} and {@code framework} strategies replace it with a value taken from
 * {@code X-Forwarded-For}, which a client can choose. {@link X509ForwardedHeadersGuard} therefore refuses to start
 * with this transport and any strategy that rewrites the address. The header of any other request is ignored, and so
 * is one that is too long or does not hold a certificate. The proxy is responsible for verifying the certificate (the
 * chain, the dates, the revocation) and for overwriting or removing a header of the same name sent by the client; the
 * server only binds the certificate it is handed by its fingerprint. The filter only looks at the sign-in request
 * ({@code POST /login/x509}).
 */
@Slf4j
public class ForwardedCertificateFilter extends OncePerRequestFilter {

    /** Name of the request attribute the servlet container, and the X.509 filter, use for the certificates. */
    static final String CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    /** Longest header value that is parsed, in characters (a certificate is a few kilobytes). */
    static final int MAX_HEADER_LENGTH = 16_384;

    /** Type of the certificates. */
    private static final String CERTIFICATE_TYPE = "X.509";

    /** Lines that frame a PEM certificate, and any white space. */
    private static final Pattern PEM_NOISE = Pattern.compile("-----(BEGIN|END) CERTIFICATE-----|\\s");

    /** Name of the header the certificate comes in. */
    private final String headerName;

    /** Matchers of the addresses of the trusted proxies. */
    private final List<IpAddressMatcher> trustedProxies;

    /** Matcher of the requests the filter looks at. */
    private final RequestMatcher loginRequests;

    /**
     * Creates the filter.
     *
     * @param properties settings of the sign-in with a certificate: the header and the trusted proxies.
     */
    public ForwardedCertificateFilter(final X509Properties properties) {
        headerName = properties.forwardedHeader();
        trustedProxies = properties.trustedProxies().stream().map(IpAddressMatcher::new).toList();
        loginRequests = PathPatternRequestMatcher.withDefaults()
                .matcher(HttpMethod.POST, X509ChainCustomizer.LOGIN_PATH);
    }

    /**
     * Sets the certificate attribute when a trusted proxy forwarded a valid certificate.
     *
     * @param request  the request.
     * @param response the response.
     * @param chain    the rest of the chain.
     * @throws ServletException if the chain fails.
     * @throws IOException      if the chain fails.
     */
    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain) throws ServletException, IOException {
        final var header = request.getHeader(headerName);
        if (header != null && loginRequests.matches(request)) {
            if (isTrusted(request.getRemoteAddr())) {
                parse(header).ifPresent(certificate -> request.setAttribute(CERTIFICATE_ATTRIBUTE,
                        new X509Certificate[] {certificate}));
            } else {
                log.warn("Ignored a forwarded client certificate from an untrusted address");
            }
        }
        chain.doFilter(request, response);
    }

    /**
     * Tells whether an address belongs to a trusted proxy.
     *
     * @param address the address of the client of the request, as the container reports it; may be {@code null}.
     * @return {@code true} when a trusted proxy matches it.
     */
    private boolean isTrusted(final String address) {
        return StringUtils.hasText(address) && trustedProxies.stream().anyMatch(proxy -> proxy.matches(address));
    }

    /**
     * Parses the certificate of a header value.
     *
     * @param value the value: the URL-encoded PEM, the PEM or the base64 of the DER form.
     * @return the certificate, or empty when the value is too long or is not a certificate.
     */
    private static Optional<X509Certificate> parse(final String value) {
        if (value.length() > MAX_HEADER_LENGTH) {
            log.debug("Ignored a forwarded client certificate that is too long");
            return Optional.empty();
        }
        try {
            final var base64 = PEM_NOISE.matcher(UriUtils.decode(value, StandardCharsets.UTF_8)).replaceAll("");
            final var der = Base64.getDecoder().decode(base64);
            final var certificate = CertificateFactory.getInstance(CERTIFICATE_TYPE)
                    .generateCertificate(new ByteArrayInputStream(der));
            return certificate instanceof X509Certificate x509 ? Optional.of(x509) : Optional.empty();
        } catch (final CertificateException | IllegalArgumentException e) {
            log.debug("Ignored a forwarded client certificate that cannot be read", e);
            return Optional.empty();
        }
    }
}
// end::x509-forwarded-filter[]
