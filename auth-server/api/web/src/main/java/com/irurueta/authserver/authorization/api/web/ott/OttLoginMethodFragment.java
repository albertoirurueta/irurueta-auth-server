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

import com.irurueta.authserver.authorization.api.web.login.LoginMethodFragment;
import org.springframework.stereotype.Component;

// tag::ott-login-fragment[]
/**
 * Contributes the one-time token sign-in to the login page: a form that asks for the identifier and whether to receive
 * a code or a magic link by e-mail, or a code by SMS, and posts it to {@code POST /ott/generate}. It renders below the
 * passkey sign-in.
 */
@Component
public class OttLoginMethodFragment implements LoginMethodFragment {

    /** Position of the one-time token sign-in in the login page: after the passkey sign-in. */
    public static final int ORDER = 300;

    /**
     * Gets the template that holds the fragment.
     *
     * @return {@code login-ott}.
     */
    @Override
    public String templateName() {
        return "login-ott";
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
}
// end::ott-login-fragment[]
