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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.web.WebAttributes;

/** Unit tests of {@link OttPagesController}. */
@ExtendWith(MockitoExtension.class)
class OttPagesControllerTest {

    /** Token of a link. */
    private static final String TOKEN = "7b7ea0e1-1b0f-4f55-8a54-2a1f3f0a1b2c";

    /** Renders the pages. */
    @Mock
    private PageRenderer pageRenderer;

    /** The request. */
    private MockHttpServletRequest request;

    /** Controller under test. */
    private OttPagesController controller;

    /** Creates the controller over a request without session. */
    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        controller = new OttPagesController(pageRenderer, request);
    }

    /** A browser that asked for a code of a sign-in gets the form that posts it to the sign-in endpoint. */
    @Test
    void ottCodePage_whenASignInCodeIsPending_rendersTheSignInForm() {
        new PendingOtt("alice", "binding", OttKind.CODE, OttPurpose.LOGIN, OttChannel.SMS)
                .saveTo(request.getSession());

        final var model = renderCode(null);

        assertEquals(true, model.get("pending"));
        assertEquals("code", model.get("kind"));
        assertEquals("sms", model.get("channel"));
        assertEquals("login", model.get("purpose"));
        assertEquals("/login/ott", model.get("postPath"));
        assertEquals("token", model.get("codeField"));
        assertEquals("/ott/generate", model.get("generatePath"));
        assertFalse(model.containsKey("errorMessageKey"));
    }

    /** A second-factor code is posted to the second-factor endpoint. */
    @Test
    void ottCodePage_whenASecondFactorCodeIsPending_rendersTheSecondFactorForm() {
        new PendingOtt("alice", "binding", OttKind.CODE, OttPurpose.SECOND_FACTOR, OttChannel.EMAIL)
                .saveTo(request.getSession());

        final var model = renderCode(null);

        assertEquals("second-factor", model.get("purpose"));
        assertEquals("/login/second-factor/ott", model.get("postPath"));
        assertEquals("code", model.get("codeField"));
    }

    /** A browser that asked for a link is told to open it. */
    @Test
    void ottCodePage_whenALinkIsPending_rendersTheLinkKind() {
        new PendingOtt("alice", "binding", OttKind.LINK, OttPurpose.LOGIN, OttChannel.EMAIL)
                .saveTo(request.getSession());

        assertEquals("link", renderCode(null).get("kind"));
    }

    /** A browser that asked for nothing still gets the same page, with the defaults. */
    @Test
    void ottCodePage_whenNothingIsPending_rendersTheDefaults() {
        final var model = renderCode(null);

        assertEquals(false, model.get("pending"));
        assertEquals("code", model.get("kind"));
        assertEquals("email", model.get("channel"));
        assertEquals("login", model.get("purpose"));
    }

    /** A failed attempt shows the generic message. */
    @Test
    void ottCodePage_whenTheAttemptFailed_showsTheGenericMessage() {
        request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new BadCredentialsException("no"));

        assertEquals("ott.error.generic", renderCode("").get("errorMessageKey"));
    }

    /** A lockout shows the locked message. */
    @Test
    void ottCodePage_whenTheAttemptFailedByLockout_showsTheLockedMessage() {
        request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new LockedException("locked"));

        assertEquals("ott.error.locked", renderCode("").get("errorMessageKey"));
    }

    /** An error flag without a session still shows the generic message. */
    @Test
    void ottCodePage_whenThereIsNoSessionButAnError_showsTheGenericMessage() {
        assertEquals("ott.error.generic", renderCode("").get("errorMessageKey"));
    }

    /** The confirmation page posts the token and is never cached nor sends a referrer. */
    @Test
    void ottConfirmPage_whenOpened_rendersTheTokenFormAndForbidsCachingAndReferrers() {
        when(pageRenderer.render(eq("ott-confirm"), anyMap())).thenReturn(ResponseEntity.ok("<html></html>"));

        final var response = controller.ottConfirmPage(TOKEN);

        assertEquals("<html></html>", response.getBody());
        assertEquals("no-store", response.getHeaders().getCacheControl());
        assertEquals("no-referrer", response.getHeaders().getFirst("Referrer-Policy"));
        final var model = ArgumentCaptor.<Map<String, ?>>captor();
        verify(pageRenderer).render(eq("ott-confirm"), model.capture());
        assertEquals(Map.of("token", TOKEN, "postPath", "/login/ott", "codeField", "token"), model.getValue());
    }

    /** The path of the page is the one of the contract. */
    @Test
    void ottCodePath_whenRead_isTheContractPath() {
        assertEquals("/login/ott", OttPagesController.OTT_CODE_PATH);
    }

    /**
     * Renders the code page and returns the model it was given.
     *
     * @param error the error flag.
     * @return the model.
     */
    private Map<String, ?> renderCode(final String error) {
        when(pageRenderer.render(eq("ott-code"), anyMap())).thenReturn(ResponseEntity.ok("<html></html>"));
        controller.ottCodePage(error);
        final var model = ArgumentCaptor.<Map<String, ?>>captor();
        verify(pageRenderer).render(eq("ott-code"), model.capture());
        return model.getValue();
    }
}
