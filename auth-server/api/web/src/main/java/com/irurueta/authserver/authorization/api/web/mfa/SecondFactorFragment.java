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

package com.irurueta.authserver.authorization.api.web.mfa;

import java.util.Map;
import org.springframework.security.core.Authentication;

// tag::mfa-second-factor-fragment[]
/**
 * Extension point that lets a second factor contribute a Thymeleaf fragment to the second-factor page. The page
 * template renders one fragment per bean, sorted by {@link #order()}, in the same way the login page renders the
 * {@link com.irurueta.authserver.authorization.api.web.login.LoginMethodFragment} beans. A fragment that depends on
 * the signed-in user (an enrolment form, a warning) contributes its data through
 * {@link #modelAttributes(Authentication)}.
 */
public interface SecondFactorFragment {

    /**
     * Gets the name of the template that holds the fragment.
     *
     * @return the template name.
     */
    String templateName();

    /**
     * Gets the name of the fragment inside the template.
     *
     * @return the fragment name.
     */
    String fragmentName();

    /**
     * Gets the position of the fragment in the page; lower values are rendered first.
     *
     * @return the order.
     */
    int order();

    /**
     * Gets the Thymeleaf fragment expression, such as {@code template :: fragment}.
     *
     * @return the fragment expression.
     */
    default String reference() {
        return templateName() + " :: " + fragmentName();
    }

    /**
     * Gets the model attributes the fragment needs for the signed-in user, added to the model of the page. Their
     * names should start with the factor's own prefix (for example {@code totp}), since every fragment shares the
     * model.
     *
     * @param authentication the authentication of the user the page is rendered for.
     * @return the attributes; none by default.
     */
    default Map<String, Object> modelAttributes(final Authentication authentication) {
        return Map.of();
    }
}
// end::mfa-second-factor-fragment[]
