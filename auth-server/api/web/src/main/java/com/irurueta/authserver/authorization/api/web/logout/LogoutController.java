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

package com.irurueta.authserver.authorization.api.web.logout;

import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Serves the page that asks the user to confirm signing out. A GET never signs the user out (it could be triggered
 * by any page); the confirmation form posts to the same path, handled by the security chain.
 */
// HTML page, not part of the OpenAPI contract
@Hidden
@Controller
public class LogoutController {

    /**
     * Renders the logout confirmation page.
     *
     * @return the logout template name.
     */
    @GetMapping(LogoutChainCustomizer.LOGOUT_PATH)
    public String logout() {
        return "logout";
    }
}
