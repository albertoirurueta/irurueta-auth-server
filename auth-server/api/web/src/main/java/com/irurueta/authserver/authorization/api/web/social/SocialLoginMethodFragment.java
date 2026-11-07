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

package com.irurueta.authserver.authorization.api.web.social;

import com.irurueta.authserver.authorization.api.web.login.LoginMethodFragment;
import java.util.List;

// tag::social-login-method-fragment[]
/**
 * Contributes the sign-in with the configured external providers to the login page: one link per enabled provider,
 * below the password form and the passkeys. The template reads {@link #providers()} through this bean, so the page
 * lists exactly the providers that are configured. The bean only exists while at least one is.
 */
public class SocialLoginMethodFragment implements LoginMethodFragment {

    /** Position of the social sign-in in the login page: after the passkeys, before the one-time tokens. */
    public static final int ORDER = 250;

    /** The enabled providers, by registration id, in the order they are offered. */
    private final List<String> providers;

    /**
     * Creates the fragment.
     *
     * @param providers registration ids of the enabled providers, in the order they are offered.
     */
    public SocialLoginMethodFragment(final List<String> providers) {
        this.providers = List.copyOf(providers);
    }

    /**
     * Gets the template that holds the fragment.
     *
     * @return {@code login-social}.
     */
    @Override
    public String templateName() {
        return "login-social";
    }

    /**
     * Gets the fragment of the template.
     *
     * @return {@code login}.
     */
    @Override
    public String fragmentName() {
        return "login";
    }

    /**
     * Gets the position of the fragment.
     *
     * @return {@link #ORDER}.
     */
    @Override
    public int order() {
        return ORDER;
    }

    /**
     * Lists the enabled providers.
     *
     * @return their registration ids, which also name the message of each link.
     */
    public List<String> providers() {
        return providers;
    }
}
// end::social-login-method-fragment[]
