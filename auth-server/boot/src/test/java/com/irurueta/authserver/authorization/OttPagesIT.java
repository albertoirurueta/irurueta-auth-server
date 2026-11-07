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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsInboxEntry;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Checks the pages of the one-time token feature, rendered through the real {@code PageRenderer} in English: the
 * sign-in fragment of the login page, the one-time token action of the second-factor page, the page where a code is
 * entered, the page a magic link opens and the phone account page with its form posts.
 */
class OttPagesIT extends AbstractMfaFlow {

    /** Path of the login page. */
    private static final String LOGIN = "/login";

    /** Path of the page where the code is entered. */
    private static final String CODE_PAGE = "/login/ott";

    /** Path of the page a magic link opens. */
    private static final String CONFIRM_PAGE = "/login/ott/confirm";

    /** Path of the phone page. */
    private static final String PHONE_PAGE = "/account/phone";

    /** Token of a link, as the e-mail carries it. */
    private static final String TOKEN = "7b7ea0e1-1b0f-4f55-8a54-2a1f3f0a1b2c";

    /** Renders pages outside a request, for the page that only exists in the dev profile. */
    @Autowired
    private PageRenderer pageRenderer;

    /** Pins the locale of the texts the tests assert on. */
    @BeforeEach
    void pinTheLocale() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
    }

    /** Restores the locale. */
    @AfterEach
    void restoreTheLocale() {
        LocaleContextHolder.resetLocaleContext();
    }

    /**
     * Verifies that the login page offers the one-time token form: the identifier, the channel and the kind, posted
     * to the token endpoint with the CSRF field and the sign-in purpose, below the password form.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void loginPage_whenRendered_offersTheOneTimeTokenForm() throws Exception {
        getMockMvc().perform(get(LOGIN))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Sign in with a code or a link")))
                .andExpect(content().string(containsString("action=\"/ott/generate\"")))
                .andExpect(content().string(containsString("name=\"purpose\" value=\"login\"")))
                .andExpect(content().string(containsString("name=\"channel\" value=\"sms\"")))
                .andExpect(content().string(containsString("name=\"kind\" value=\"link\"")))
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(containsString("for=\"ott-username\"")));
    }

    /**
     * Verifies that the second-factor page offers a code and a link by e-mail, and no SMS, to a user whose
     * multi-factor authentication was forced without any second factor enrolled: the e-mail is then the only second
     * factor available.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactorPage_whenUserHasNoSecondFactorAndNoPhone_offersEmailOnly() throws Exception {
        final var user = getFixtures().createUser();
        getFixtures().requireMfa(user, getTools());
        final var session = signInWithThePassword(user);

        getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("E-mail me a code")))
                .andExpect(content().string(containsString("E-mail me a link")))
                .andExpect(content().string(containsString("name=\"purpose\" value=\"second-factor\"")))
                .andExpect(content().string(not(containsString("Send me a code by SMS"))));
    }

    /**
     * Verifies that the second-factor page does not offer the e-mail to a user with another confirmed second factor
     * (an authenticator app here): a mailbox, which also resets the password, never stands in for it.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactorPage_whenUserHasAnotherSecondFactor_doesNotOfferEmail() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var session = signInWithThePassword(enrolled.user());

        getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("E-mail me a code"))))
                .andExpect(content().string(not(containsString("E-mail me a link"))));
    }

    /**
     * Verifies that the page where a code is entered says to check the inbox and shows the code form, with an error
     * announced in a live region only after a failed attempt.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void codePage_whenRendered_showsTheCodeFormAndAnnouncesAnError() throws Exception {
        getMockMvc().perform(get(CODE_PAGE))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Check your inbox")))
                .andExpect(content().string(containsString("action=\"/login/ott\"")))
                .andExpect(content().string(containsString("name=\"token\"")))
                .andExpect(content().string(containsString("autocomplete=\"one-time-code\"")))
                .andExpect(content().string(not(containsString("The code or the link is not valid."))));

        getMockMvc().perform(get(CODE_PAGE).param("error", ""))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("aria-live=\"assertive\"")))
                .andExpect(content().string(containsString("The code or the link is not valid.")));
    }

    /**
     * Verifies that the page a magic link opens only shows a button whose form posts the token, and that it is never
     * cached.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void confirmPage_whenRendered_postsTheTokenWithAButton() throws Exception {
        getMockMvc().perform(get(CONFIRM_PAGE).param("token", TOKEN))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(content().string(containsString("action=\"/login/ott\"")))
                .andExpect(content().string(containsString("name=\"token\" value=\"" + TOKEN + "\"")))
                .andExpect(content().string(containsString("Continue")));
    }

    /**
     * Verifies the phone page and its posts: anonymous visitors are sent to sign in, a signed-in user sees the
     * enrolment forms, a number is accepted (the answer never says whether it is registered), a wrong code and an
     * invalid number are reported on the page and a status the page does not know is ignored.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void phonePage_whenUserIsSignedIn_enrolsAndReportsOutcomes() throws Exception {
        getMockMvc().perform(get(PHONE_PAGE))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));

        final var user = getFixtures().createUser();
        final var session = new MockHttpSession();
        getFixtures().signIn(user, session);

        getMockMvc().perform(get(PHONE_PAGE).session(session))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(content().string(containsString("Add a phone")))
                .andExpect(content().string(containsString("action=\"/account/phone\"")))
                .andExpect(content().string(containsString("action=\"/account/phone/verify\"")))
                .andExpect(content().string(containsString("name=\"_csrf\"")));

        getMockMvc().perform(form(PHONE_PAGE, session, "phone", "+34 600 111 222"))
                .andExpect(status().isSeeOther())
                .andExpect(redirectedUrl("/account/phone?status=pending"));
        getMockMvc().perform(get(PHONE_PAGE).param("status", "pending").session(session))
                .andExpect(content().string(containsString("a code is on its way")));

        getMockMvc().perform(form(PHONE_PAGE + "/verify", session, "code", "000000"))
                .andExpect(status().isSeeOther())
                .andExpect(redirectedUrl("/account/phone?status=invalid-code"));
        getMockMvc().perform(form(PHONE_PAGE, session, "phone", "not a number"))
                .andExpect(status().isSeeOther())
                .andExpect(redirectedUrl("/account/phone?status=invalid-phone"));
        getMockMvc().perform(get(PHONE_PAGE).param("status", "<script>").session(session))
                .andExpect(content().string(not(containsString("<script>"))));
        getMockMvc().perform(post(PHONE_PAGE + "/remove").session(session).with(csrf()))
                .andExpect(status().isSeeOther())
                .andExpect(redirectedUrl("/account/phone?status=removed"));
    }

    /**
     * Verifies that a form post of the phone page without the CSRF token is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void phonePost_whenTheCsrfTokenIsMissing_isRefused() throws Exception {
        final var session = new MockHttpSession();
        getFixtures().signIn(getFixtures().createUser(), session);

        getMockMvc().perform(post(PHONE_PAGE + "/remove").session(session))
                .andExpect(status().isForbidden());
    }

    /**
     * Verifies the template of the development SMS inbox (its controller only exists in the dev profile, which the
     * integration tests do not run): the recorded messages are listed in a table with headers, and an empty inbox
     * says so.
     */
    @Test
    void devSmsInboxTemplate_whenRendered_listsTheMessagesOrSaysThereAreNone() {
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));
        try {
            final var entry = new SmsInboxEntry(new PhoneNumber("+34600111222"), "Your code is 123456",
                    Instant.parse("2026-01-01T00:00:00Z"));
            final var listed = pageRenderer.render("dev-sms-inbox", Map.of("messages", List.of(entry))).getBody();
            final var empty = pageRenderer.render("dev-sms-inbox", Map.of("messages", List.of())).getBody();

            assertTrue(listed.contains("<th scope=\"col\">To</th>"));
            assertTrue(listed.contains("+34600111222"));
            assertTrue(listed.contains("Your code is 123456"));
            assertTrue(empty.contains("No messages yet."));
            assertFalse(empty.contains("<table"));
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    /**
     * Builds the post a browser makes when it submits a form of the phone page.
     *
     * @param path    path the form posts to.
     * @param session the browser session.
     * @param name    name of the only field.
     * @param value   value of the field.
     * @return the request.
     */
    private static MockHttpServletRequestBuilder form(final String path, final MockHttpSession session,
            final String name, final String value) {
        return post(path).session(session).with(csrf()).contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param(name, value);
    }

    /**
     * Signs a user in with the password only, leaving the session at the second-factor step.
     *
     * @param user the user.
     * @return the session.
     * @throws Exception if a request cannot be performed.
     */
    private MockHttpSession signInWithThePassword(final AuthServerFixtures.TestUser user) throws Exception {
        final var session = new MockHttpSession();
        signInForAuthorization(user, getFixtures().createMfaCodeClient(), newVerifier(), Map.of(), session);
        return session;
    }
}
