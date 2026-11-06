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

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.LoginPageApi;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;

/**
 * Serves the login page, as the contract {@code apis/auth-server/web-pages/auth-server-pages-v1.yaml} describes it
 * through the generated {@link LoginPageApi}, supplying the ordered login method fragments and the outcome of the last
 * attempt to the template.
 */
@Controller
public class LoginController implements LoginPageApi {

    /**
     * Path of the login page, which also receives the form post. The single source of the path for the security
     * chains and the template, taken from the contract.
     */
    public static final String LOGIN_PATH = PATH_LOGIN_PAGE;

    /** Name of the login template. */
    static final String VIEW_NAME = "login";

    /** Name of the model attribute that holds the path the login form posts to. */
    static final String LOGIN_PATH_ATTRIBUTE = "loginPath";

    /** Name of the model attribute that holds the fragments of the login methods. */
    static final String FRAGMENTS_ATTRIBUTE = "fragments";

    /** Name of the model attribute that holds the key of the message of a failed sign-in. */
    static final String ERROR_MESSAGE_ATTRIBUTE = "errorMessageKey";

    /** Name of the model attribute that tells the user has just signed out. */
    static final String LOGGED_OUT_ATTRIBUTE = "loggedOut";

    /** Fragments contributed by the authentication methods, sorted by order. */
    private final List<LoginMethodFragment> fragments;

    /** Maps the last authentication exception to a message key. */
    private final LoginErrorMessages errorMessages;

    /** Renders the page. */
    private final PageRenderer pageRenderer;

    /** The current request, injected as a thread-bound proxy, whose session holds the last failure. */
    private final HttpServletRequest request;

    /**
     * Creates the controller.
     *
     * @param methods       fragments contributed by the authentication methods.
     * @param errorMessages mapper of the authentication exceptions to message keys.
     * @param pageRenderer  renderer of the page.
     * @param request       the current request.
     */
    public LoginController(final List<LoginMethodFragment> methods, final LoginErrorMessages errorMessages,
            final PageRenderer pageRenderer, final HttpServletRequest request) {
        this.fragments = methods.stream().sorted(Comparator.comparingInt(LoginMethodFragment::order)).toList();
        this.errorMessages = errorMessages;
        this.pageRenderer = pageRenderer;
        this.request = request;
    }

    // tag::login-controller[]
    /**
     * Renders the login page.
     *
     * @param error  present (even if empty) when the previous attempt failed.
     * @param logout present (even if empty) when the user has just signed out.
     * @return the login page.
     */
    @Override
    public ResponseEntity<String> loginPage(final String error, final String logout) {
        final var model = new HashMap<String, Object>();
        model.put(LOGIN_PATH_ATTRIBUTE, LOGIN_PATH);
        model.put(FRAGMENTS_ATTRIBUTE, fragments);
        if (error != null) {
            model.put(ERROR_MESSAGE_ATTRIBUTE, errorMessages.keyOf(lastFailure()));
        }
        model.put(LOGGED_OUT_ATTRIBUTE, logout != null);
        return pageRenderer.render(VIEW_NAME, model);
    }
    // end::login-controller[]

    /**
     * Gets the exception of the previous failed attempt, which Spring Security keeps in the session.
     *
     * @return the exception, or {@code null} when there is no session or it holds none.
     */
    private AuthenticationException lastFailure() {
        final var session = request.getSession(false);
        final var failure = session == null ? null : session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        return failure instanceof final AuthenticationException exception ? exception : null;
    }
}
