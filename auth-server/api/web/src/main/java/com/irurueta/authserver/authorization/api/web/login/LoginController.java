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
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Serves the login page, supplying the ordered login method fragments to the template.
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

    /** Fragments contributed by the authentication methods, sorted by order. */
    private final List<LoginMethodFragment> fragments;

    /**
     * Creates the controller.
     *
     * @param methods fragments contributed by the authentication methods.
     */
    public LoginController(final List<LoginMethodFragment> methods) {
        this.fragments = methods.stream().sorted(Comparator.comparingInt(LoginMethodFragment::order)).toList();
    }

    /**
     * Renders the login page.
     *
     * @param model model of the view.
     * @return the login template name.
     */
    @GetMapping(LOGIN_PATH)
    public String login(final Model model) {
        model.addAttribute(LOGIN_PATH_ATTRIBUTE, LOGIN_PATH);
        model.addAttribute("fragments", fragments);
        return "login";
    }
}
