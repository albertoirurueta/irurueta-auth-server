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

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.LogoutPageApi;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;

/**
 * Serves the page that asks the user to confirm signing out, as the contract
 * {@code apis/auth-server/web-pages/auth-server-pages-v1.yaml} describes it through the generated
 * {@link LogoutPageApi}. A GET never signs the user out (it could be triggered by any page); the confirmation form
 * posts to the same path, handled by the security chain.
 */
@Controller
@RequiredArgsConstructor
public class LogoutController implements LogoutPageApi {

    /** Name of the logout template. */
    static final String VIEW_NAME = "logout";

    /** Renders the page. */
    private final PageRenderer pageRenderer;

    /**
     * Renders the logout confirmation page.
     *
     * @return the logout confirmation page.
     */
    @Override
    public ResponseEntity<String> logoutPage() {
        return pageRenderer.render(VIEW_NAME, Map.of());
    }
}
