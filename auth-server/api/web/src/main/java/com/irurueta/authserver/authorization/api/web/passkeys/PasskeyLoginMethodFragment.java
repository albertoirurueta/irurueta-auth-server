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

package com.irurueta.authserver.authorization.api.web.passkeys;

import com.irurueta.authserver.authorization.api.web.login.LoginMethodFragment;
import org.springframework.stereotype.Component;

/**
 * Contributes the passkey sign-in to the login page: a button and a field the browser fills with the passkeys it
 * knows (conditional mediation). It is rendered below the password form.
 */
@Component
public class PasskeyLoginMethodFragment implements LoginMethodFragment {

    /** Position of the passkey sign-in in the login page: after the password form. */
    public static final int ORDER = 200;

    /**
     * Gets the template that holds the fragment.
     *
     * @return {@code passkeys}.
     */
    @Override
    public String templateName() {
        return "passkeys";
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
