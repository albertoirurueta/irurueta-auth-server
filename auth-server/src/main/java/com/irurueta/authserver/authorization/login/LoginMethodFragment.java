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

package com.irurueta.authserver.authorization.login;

/**
 * Extension point that lets an authentication method contribute a Thymeleaf fragment to the login page.
 * The login template renders one fragment per bean, sorted by {@link #order()}.
 */
public interface LoginMethodFragment {

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
     * Gets the position of the fragment in the login page; lower values are rendered first.
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
}
