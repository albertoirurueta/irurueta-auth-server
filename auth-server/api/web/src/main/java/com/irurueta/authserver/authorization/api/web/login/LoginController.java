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

import io.swagger.v3.oas.annotations.Hidden;
import java.util.Comparator;
import java.util.List;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;

/**
 * Serves the login page, supplying the ordered login method fragments and the outcome of the last attempt to the
 * template.
 */
// HTML page, not part of the OpenAPI contract
@Hidden
@Controller
public class LoginController {

    /**
     * Path of the login page, which also receives the form post. The single source of the path: the security
     * chains and the template use it too.
     */
    public static final String LOGIN_PATH = "/login";

    /** Name of the model attribute that holds the path the login form posts to. */
    static final String LOGIN_PATH_ATTRIBUTE = "loginPath";

    /** Name of the model attribute that holds the key of the message of a failed sign-in. */
    static final String ERROR_MESSAGE_ATTRIBUTE = "errorMessageKey";

    /** Name of the model attribute that tells the user has just signed out. */
    static final String LOGGED_OUT_ATTRIBUTE = "loggedOut";

    /** Fragments contributed by the authentication methods, sorted by order. */
    private final List<LoginMethodFragment> fragments;

    /** Maps the last authentication exception to a message key. */
    private final LoginErrorMessages errorMessages;

    /**
     * Creates the controller.
     *
     * @param methods       fragments contributed by the authentication methods.
     * @param errorMessages mapper of the authentication exceptions to message keys.
     */
    public LoginController(final List<LoginMethodFragment> methods, final LoginErrorMessages errorMessages) {
        this.fragments = methods.stream().sorted(Comparator.comparingInt(LoginMethodFragment::order)).toList();
        this.errorMessages = errorMessages;
    }

    /**
     * Renders the login page.
     *
     * @param model     model of the view.
     * @param error     present (even if empty) when the previous attempt failed.
     * @param logout    present (even if empty) when the user has just signed out.
     * @param exception exception of the previous failed attempt, kept in the session by Spring Security.
     * @return the login template name.
     */
    @GetMapping(LOGIN_PATH)
    public String login(
            final Model model,
            @RequestParam(name = "error", required = false) final String error,
            @RequestParam(name = "logout", required = false) final String logout,
            @SessionAttribute(name = WebAttributes.AUTHENTICATION_EXCEPTION, required = false)
            final AuthenticationException exception) {
        model.addAttribute(LOGIN_PATH_ATTRIBUTE, LOGIN_PATH);
        model.addAttribute("fragments", fragments);
        if (error != null) {
            model.addAttribute(ERROR_MESSAGE_ATTRIBUTE, errorMessages.keyOf(exception));
        }
        model.addAttribute(LOGGED_OUT_ATTRIBUTE, logout != null);
        return "login";
    }
}
