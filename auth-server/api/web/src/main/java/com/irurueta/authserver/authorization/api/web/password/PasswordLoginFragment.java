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

package com.irurueta.authserver.authorization.api.web.password;

import com.irurueta.authserver.authorization.api.web.login.LoginMethodFragment;
import org.springframework.stereotype.Component;

/**
 * Contributes the username and password form to the login page, as every authentication method does through the
 * {@link LoginMethodFragment} extension point. It is rendered first.
 *
 * <p>The fragments of the methods that follow use the matching {@code autocomplete} tokens on their inputs:
 * {@code one-time-code} for the one-time token and TOTP codes and {@code webauthn} (together with
 * {@code username}) for passkeys.
 */
@Component
public class PasswordLoginFragment implements LoginMethodFragment {

    /** Position of the password form in the login page. */
    public static final int ORDER = 100;

    @Override
    public String templateName() {
        return "password";
    }

    @Override
    public String fragmentName() {
        return "form";
    }

    @Override
    public int order() {
        return ORDER;
    }
}
