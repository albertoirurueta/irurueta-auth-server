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

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.PasskeysPageApi;
import com.irurueta.authserver.authorization.application.passkeys.ListPasskeysUseCase;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;

/**
 * Renders the account page where the signed-in user registers passkeys. The registration itself is the WebAuthn
 * ceremony of the security chain, driven by the script of the page; this page only lists what is registered.
 */
@Controller
@RequiredArgsConstructor
public class PasskeysPageController implements PasskeysPageApi {

    /** Path of the page, taken from the contract. */
    public static final String PASSKEYS_PATH = PATH_PASSKEYS_PAGE;

    /** Name of the template of the page. */
    static final String VIEW_NAME = "account-passkeys";

    /** Name of the model attribute that holds the passkeys already registered. */
    static final String PASSKEYS_ATTRIBUTE = "passkeys";

    /** Resolves the account of the request. */
    private final CurrentAccountResolver currentAccountResolver;

    /** Lists the passkeys of an account. */
    private final ListPasskeysUseCase listPasskeysUseCase;

    /** Maps the passkeys onto the view model. */
    private final PasskeyViewMapper passkeyViewMapper;

    /** Renders the page. */
    private final PageRenderer pageRenderer;

    // tag::passkeys-page-controller[]
    /**
     * Renders the page.
     *
     * @return the passkeys page, with the passkeys of the signed-in user.
     */
    @Override
    public ResponseEntity<String> passkeysPage() {
        final var account = currentAccountResolver.resolve();
        return pageRenderer.render(VIEW_NAME,
                Map.of(PASSKEYS_ATTRIBUTE, passkeyViewMapper.toViews(listPasskeysUseCase.execute(account.username()))));
    }
    // end::passkeys-page-controller[]
}
