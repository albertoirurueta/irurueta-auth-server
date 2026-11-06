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

package com.irurueta.authserver.authorization;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.SecurityConfig;
import com.irurueta.authserver.authorization.api.web.login.BrandingConfiguration;
import com.irurueta.authserver.authorization.api.web.login.BrandingProvider;
import com.irurueta.authserver.authorization.api.web.login.LoginContentSecurityPolicy;
import com.irurueta.authserver.authorization.api.web.login.LoginController;
import com.irurueta.authserver.authorization.api.web.login.LoginErrorMessages;
import com.irurueta.authserver.authorization.api.web.login.LoginHeadersCustomizer;
import com.irurueta.authserver.authorization.api.web.login.LoginStaticResourcesCustomizer;
import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.password.PasswordLoginFragment;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Checks, in a web slice with a branding logo served by another origin, that the login page renders the logo and that
 * its content security policy allows that origin for images, and only for images. It is an integration test because
 * it starts a Spring context.
 */
@WebMvcTest(controllers = LoginController.class)
@Import({SecurityConfig.class, PageRenderer.class, BrandingProvider.class, LoginHeadersCustomizer.class,
        LoginContentSecurityPolicy.class, LoginStaticResourcesCustomizer.class, LoginErrorMessages.class,
        PasswordLoginFragment.class, BrandingConfiguration.class, SecurityConfigIT.TestBeans.class})
@TestPropertySource(properties = "authserver.ui.branding.logo-url=" + LoginContentSecurityPolicyIT.LOGO_URL)
class LoginContentSecurityPolicyIT {

    /** Logo served by another origin than the authorization server. */
    static final String LOGO_URL = "https://cdn.example.com:8443/brand/logo.svg";

    /** MockMvc bound to the web slice. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that the login page shows the logo and allows its origin as an image source.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void login_whenLogoIsOnAnotherOrigin_allowsThatOriginForImages() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("src=\"" + LOGO_URL + "\"")))
                .andExpect(header().string("Content-Security-Policy",
                        "default-src 'self'; frame-ancestors 'none'; img-src 'self' https://cdn.example.com:8443"));
    }
}
