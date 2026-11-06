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
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import jakarta.servlet.RequestDispatcher;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Checks, in the running application, that Spring Boot's error controller renders the custom error page through
 * {@code ErrorPageViewResolver}, is reachable without signing in and never renders the details of a failure, neither
 * in the page nor in the JSON body.
 */
@PostgresIT
@AutoConfigureMockMvc
class ErrorPageIT {

    /** Status of the simulated failure. */
    private static final int NOT_FOUND = 404;

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that the error page is public, keeps the status and shows a generic text without the exception.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void errorPage_whenRequestedAnonymouslyAsHtml_showsGenericTextWithoutDetails() throws Exception {
        mockMvc.perform(get("/error").accept(MediaType.TEXT_HTML)
                        .requestAttr(RequestDispatcher.ERROR_STATUS_CODE, NOT_FOUND)
                        .requestAttr(RequestDispatcher.ERROR_EXCEPTION, new IllegalStateException("secret detail")))
                .andExpect(status().isNotFound())
                .andExpect(content().string(containsString("does not exist")))
                .andExpect(content().string(not(containsString("secret detail"))))
                .andExpect(content().string(not(containsString("IllegalStateException"))));
    }

    /**
     * Verifies that a client that does not accept HTML gets the status only: no message, exception, stack trace or
     * path.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void errorPage_whenRequestedAsJson_returnsStatusOnly() throws Exception {
        mockMvc.perform(get("/error").accept(MediaType.APPLICATION_JSON)
                        .requestAttr(RequestDispatcher.ERROR_STATUS_CODE, NOT_FOUND)
                        .requestAttr(RequestDispatcher.ERROR_REQUEST_URI, "/internal/secret-path")
                        .requestAttr(RequestDispatcher.ERROR_EXCEPTION, new IllegalStateException("secret detail")))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(NOT_FOUND))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").doesNotExist())
                .andExpect(jsonPath("$.exception").doesNotExist())
                .andExpect(jsonPath("$.trace").doesNotExist())
                .andExpect(jsonPath("$.path").doesNotExist())
                .andExpect(content().string(not(containsString("secret"))));
    }
}
