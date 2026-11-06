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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import com.irurueta.authserver.authorization.api.web.SecurityConfig;
import com.irurueta.authserver.authorization.api.web.login.BrandingConfiguration;
import com.irurueta.authserver.authorization.api.web.login.LoginContentSecurityPolicy;
import com.irurueta.authserver.authorization.api.web.login.LoginController;
import com.irurueta.authserver.authorization.api.web.login.LoginErrorMessages;
import com.irurueta.authserver.authorization.api.web.login.LoginHeadersCustomizer;
import com.irurueta.authserver.authorization.api.web.login.LoginStaticResourcesCustomizer;
import com.irurueta.authserver.authorization.api.web.password.PasswordLoginFragment;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Checks the login page in a web slice with the real password fragment: what it renders, CSRF protection, the
 * outcome of a failed sign-in and the return to the saved authorization request. It is an integration test because it
 * starts a Spring context.
 */
@WebMvcTest(controllers = LoginController.class)
@Import({SecurityConfig.class, LoginHeadersCustomizer.class, LoginContentSecurityPolicy.class,
        LoginStaticResourcesCustomizer.class, LoginErrorMessages.class, PasswordLoginFragment.class,
        BrandingConfiguration.class, SecurityConfigIT.TestBeans.class})
class LoginPageIT {

    /** Username of the in-memory user of the slice. */
    private static final String USERNAME = "u";

    /** Clear-text password of the in-memory user of the slice; not a real credential. */
    private static final String PASSWORD = "p";

    /** Path of the login page. */
    private static final String LOGIN = "/login";

    /** Name of the form parameter that carries the username. */
    private static final String USERNAME_PARAM = "username";

    /** Name of the form parameter that carries the password. */
    private static final String PASSWORD_PARAM = "password";

    /** Text of the generic error message. */
    private static final String GENERIC_MESSAGE = "Invalid username or password.";

    /** MockMvc bound to the web slice. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Provides each failed sign-in the page distinguishes, with the text it must show.
     *
     * @return the exception and the expected text.
     */
    private static Stream<Object[]> failures() {
        return Stream.of(
                new Object[] {new BadCredentialsException("x"), GENERIC_MESSAGE},
                new Object[] {new LockedException("x"), "This account is locked."},
                new Object[] {new AccountExpiredException("x"), "This account has expired."},
                new Object[] {new CredentialsExpiredException("x"), "Your password has expired."},
                new Object[] {new DisabledException("x"), "This account is disabled."});
    }

    /**
     * Verifies that the page uses the layout and renders the password form, with the autocomplete hints and the CSRF
     * token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenRequested_rendersPasswordFormOnTheLayout() throws Exception {
        mockMvc.perform(get(LOGIN))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("<title>Sign in</title>")))
                .andExpect(content().string(containsString("class=\"branding\"")))
                .andExpect(content().string(containsString("autocomplete=\"username\"")))
                .andExpect(content().string(containsString("autocomplete=\"current-password\"")))
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(not(containsString("role=\"alert\""))));
    }

    /**
     * Verifies that a post without the CSRF token is forbidden.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void formLogin_whenCsrfTokenIsMissing_isForbidden() throws Exception {
        mockMvc.perform(post(LOGIN).param(USERNAME_PARAM, USERNAME).param(PASSWORD_PARAM, PASSWORD))
                .andExpect(status().isForbidden());
    }

    /**
     * Verifies that bad credentials redirect to the error page, which shows the generic message.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void formLogin_whenPasswordIsWrong_redirectsToErrorWithGenericMessage() throws Exception {
        final var session = failedLogin(USERNAME, "wrong");

        mockMvc.perform(get(LOGIN).queryParam("error", "").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(GENERIC_MESSAGE)));
    }

    /**
     * Verifies that an unknown user and a wrong password get the identical response, so the page never reveals
     * whether an account exists.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void formLogin_whenUserIsUnknown_getsTheSameResponseAsAWrongPassword() throws Exception {
        final var wrongPassword = mockMvc.perform(get(LOGIN).queryParam("error", "")
                        .session(failedLogin(USERNAME, "wrong")))
                .andReturn().getResponse().getContentAsString();
        final var unknownUser = mockMvc.perform(get(LOGIN).queryParam("error", "")
                        .session(failedLogin("nobody", "wrong")))
                .andReturn().getResponse().getContentAsString();

        // the CSRF token differs between sessions, so compare the visible message and the page without the token
        assertEquals(stripToken(wrongPassword), stripToken(unknownUser));
    }

    /**
     * Verifies the message of every kind of failed sign-in.
     *
     * @param exception the failure kept in the session by Spring Security.
     * @param text      the message the page must show.
     * @throws Exception if a request cannot be performed.
     */
    @ParameterizedTest
    @MethodSource("failures")
    void login_whenErrorIsRequested_showsTheMessageOfTheFailure(
            final AuthenticationException exception, final String text) throws Exception {
        mockMvc.perform(get(LOGIN).queryParam("error", "")
                        .sessionAttr(WebAttributes.AUTHENTICATION_EXCEPTION, exception))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("role=\"alert\"")))
                .andExpect(content().string(containsString(text)));
    }

    /**
     * Verifies that the page tells the user has signed out.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenLogoutIsRequested_showsTheSignedOutStatus() throws Exception {
        mockMvc.perform(get(LOGIN).queryParam("logout", ""))
                .andExpect(content().string(containsString("You have been signed out.")));
    }

    /**
     * Verifies that a successful sign-in returns to the authorization request that was saved before the redirect to
     * the login page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void formLogin_whenAuthorizationRequestWasSaved_returnsToIt() throws Exception {
        final var session = (MockHttpSession) mockMvc.perform(get("/oauth2/authorize?response_type=code&client_id=c"
                        + "&redirect_uri=http://localhost/cb"
                        + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString(LOGIN)))
                .andReturn().getRequest().getSession();

        mockMvc.perform(post(LOGIN).session(session).with(csrf())
                        .param(USERNAME_PARAM, USERNAME).param(PASSWORD_PARAM, PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/oauth2/authorize?response_type=code")));
    }

    /**
     * Performs a failed sign-in and returns the session that holds its exception.
     *
     * @param username username to post.
     * @param password password to post.
     * @return the session of the failed attempt.
     * @throws Exception if a request cannot be performed.
     */
    private MockHttpSession failedLogin(final String username, final String password) throws Exception {
        return (MockHttpSession) mockMvc.perform(post(LOGIN).with(csrf())
                        .param(USERNAME_PARAM, username).param(PASSWORD_PARAM, password))
                .andExpect(redirectedUrl("/login?error"))
                .andReturn().getRequest().getSession();
    }

    /**
     * Removes the CSRF token value from a page.
     *
     * @param html the page.
     * @return the page without the token value.
     */
    private static String stripToken(final String html) {
        return html.replaceAll("name=\"_csrf\" value=\"[^\"]*\"", "name=\"_csrf\"");
    }
}
