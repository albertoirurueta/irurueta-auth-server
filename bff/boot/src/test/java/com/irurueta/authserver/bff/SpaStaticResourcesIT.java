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

package com.irurueta.authserver.bff;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration tests of the single page application the BFF serves.
 */
@PostgresIT
@AutoConfigureMockMvc
class SpaStaticResourcesIT {

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that the page is served to an anonymous visitor, with no inline script.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void index_whenRequestedAnonymously_isServedWithoutInlineScript() throws Exception {
        mockMvc.perform(get("/index.html"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("<html lang=\"en\">")))
                .andExpect(content().string(containsString("src=\"/assets/app.js\"")))
                .andExpect(content().string(not(containsString("onclick"))));
    }

    /**
     * Verifies that the page carries the hidden retry link the script reveals after a failed sign-in.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void index_whenRequested_hasRetryLinkForFailedSignIn() throws Exception {
        mockMvc.perform(get("/index.html"))
                .andExpect(content().string(containsString("id=\"retry\"")));
    }

    /**
     * Verifies that the page carries the hidden signed-out state, with a Sign in button, that the script shows instead
     * of starting the sign-in by itself.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void index_whenRequested_hasSignedOutStateWithSignInButton() throws Exception {
        mockMvc.perform(get("/index.html"))
                .andExpect(content().string(containsString("<section id=\"signed-out\"")))
                .andExpect(content().string(containsString("<button type=\"button\" id=\"sign-in\">Sign in</button>")));
    }

    /**
     * Verifies that the script signs out with a form POST carrying the CSRF token as a parameter, and never reads a
     * logout URL from a response body.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void appScript_whenRequested_signsOutWithAFormPost() throws Exception {
        mockMvc.perform(get("/assets/app.js"))
                .andExpect(content().string(containsString("form.action = '/bff/logout'")))
                .andExpect(content().string(containsString("'_csrf'")))
                .andExpect(content().string(not(containsString("logoutUrl"))));
    }

    /**
     * Verifies that the root path serves the page to an anonymous visitor.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void root_whenRequestedAnonymously_isServed() throws Exception {
        mockMvc.perform(get("/")).andExpect(status().isOk());
    }

    /**
     * Verifies that the script and the style sheet are public too.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void assets_whenRequestedAnonymously_areServed() throws Exception {
        mockMvc.perform(get("/assets/app.js")).andExpect(status().isOk());
        mockMvc.perform(get("/assets/styles.css")).andExpect(status().isOk());
    }

    /**
     * Verifies that serving the page does not open the API: it still needs a session.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void api_whenRequestedAnonymously_isUnauthorized() throws Exception {
        mockMvc.perform(get("/api/documents")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/bff/user")).andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that the content security policy only allows same-origin scripts and forbids framing.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void index_whenRequested_carriesContentSecurityPolicy() throws Exception {
        mockMvc.perform(get("/index.html"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'self'")))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")));
    }
}
