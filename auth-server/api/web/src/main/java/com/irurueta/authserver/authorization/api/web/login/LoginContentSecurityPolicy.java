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

package com.irurueta.authserver.authorization.api.web.login;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

// tag::login-csp[]
/**
 * Builds the content security policy of the server-rendered pages from the {@link BrandingProperties}: same-origin
 * resources only and no framing, plus, when the branding logo is an absolute {@code http(s)} URL, its origin as an
 * allowed image source ({@code img-src 'self' <scheme://host[:port]>}). A relative logo URL is same-origin and needs
 * nothing more.
 */
@Component
@RequiredArgsConstructor
public class LoginContentSecurityPolicy {

    /** Policy of the pages when the logo, if any, is served by this application. */
    public static final String DEFAULT_POLICY = "default-src 'self'; frame-ancestors 'none'";

    /** Directive prefix that allows images from this application, followed by the origin of the logo. */
    static final String IMAGE_SOURCE_PREFIX = "; img-src 'self' ";

    /** Schemes whose origin is added for an absolute logo URL. */
    private static final Set<String> WEB_SCHEMES = Set.of("http", "https");

    /** Provider of the configured branding; absent in web slices that do not enable the properties. */
    private final ObjectProvider<BrandingProperties> branding;

    /**
     * Builds the policy.
     *
     * @return {@link #DEFAULT_POLICY}, followed by an {@code img-src} directive with the logo's origin when the logo
     *         is an absolute {@code http(s)} URL.
     */
    public String policy() {
        final var logoUrl = branding.getIfAvailable(() -> new BrandingProperties(null, null, null)).logoUrl();
        return originOf(logoUrl).map(origin -> DEFAULT_POLICY + IMAGE_SOURCE_PREFIX + origin).orElse(DEFAULT_POLICY);
    }

    /**
     * Extracts the origin of an absolute {@code http(s)} URL.
     *
     * @param url the URL; may be empty.
     * @return {@code scheme://host[:port]} in lower case, or empty when the URL is relative, not {@code http(s)},
     *         has no host or cannot be parsed.
     */
    private static Optional<String> originOf(final String url) {
        try {
            final var uri = new URI(url);
            final var scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if (!WEB_SCHEMES.contains(scheme) || uri.getHost() == null) {
                return Optional.empty();
            }
            final var port = uri.getPort() < 0 ? "" : ":" + uri.getPort();
            return Optional.of(scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + port);
        } catch (final URISyntaxException invalid) {
            return Optional.empty();
        }
    }
}
// end::login-csp[]
