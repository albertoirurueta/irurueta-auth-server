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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Reads the PEM files of the trusted certificate authorities into trust anchors. A file may hold several
 * certificates.
 */
@Component
public class TrustAnchorsReader {

    /** Type of the certificates. */
    private static final String CERTIFICATE_TYPE = "X.509";

    /**
     * Reads the files.
     *
     * @param paths paths of the PEM files.
     * @return the trust anchors of every certificate of every file.
     * @throws IllegalArgumentException if a file cannot be read or holds no certificate, so a misconfigured server
     *                                  fails at startup instead of refusing every client.
     */
    public MtlsTrustAnchors read(final List<String> paths) {
        final var anchors = new HashSet<TrustAnchor>();
        for (final var path : paths) {
            try (InputStream in = Files.newInputStream(Path.of(path))) {
                final var certificates = CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertificates(in);
                if (certificates.isEmpty()) {
                    throw new IllegalArgumentException("No certificate found in " + path);
                }
                certificates.forEach(certificate -> anchors.add(new TrustAnchor((X509Certificate) certificate, null)));
            } catch (IOException | CertificateException e) {
                throw new IllegalArgumentException("Cannot read the trusted authority " + path, e);
            }
        }
        return new MtlsTrustAnchors(anchors);
    }
}
