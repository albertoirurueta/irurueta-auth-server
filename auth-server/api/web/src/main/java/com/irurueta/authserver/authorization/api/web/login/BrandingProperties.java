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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

// tag::login-branding[]
/**
 * Branding shown by the login, consent, logout and error pages, bound from {@code authserver.ui.branding.*}.
 *
 * @param applicationName name shown in the page header and title; defaults to {@link #DEFAULT_APPLICATION_NAME}.
 * @param logoUrl         optional URL of a logo image served by this application; empty when there is none.
 * @param footerText      optional text shown below every page; empty when there is none.
 */
@ConfigurationProperties("authserver.ui.branding")
public record BrandingProperties(String applicationName, String logoUrl, String footerText) {

    /** Application name used when none is configured. */
    public static final String DEFAULT_APPLICATION_NAME = "Irurueta Auth Server";

    /**
     * Applies the defaults.
     *
     * @param applicationName name shown in the page header, blank for the default.
     * @param logoUrl         optional logo URL, blank for none.
     * @param footerText      optional footer text, blank for none.
     */
    public BrandingProperties {
        applicationName = StringUtils.hasText(applicationName) ? applicationName : DEFAULT_APPLICATION_NAME;
        logoUrl = StringUtils.hasText(logoUrl) ? logoUrl : "";
        footerText = StringUtils.hasText(footerText) ? footerText : "";
    }
}
// end::login-branding[]
