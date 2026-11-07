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

import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Maps the passkeys of the domain onto the view model of the passkeys page.
 */
@Component
public class PasskeyViewMapper {

    /**
     * Maps several passkeys, keeping their order.
     *
     * @param passkeys the passkeys.
     * @return their views.
     */
    public List<PasskeyView> toViews(final List<Passkey> passkeys) {
        return passkeys.stream()
                .map(passkey -> new PasskeyView(passkey.label(), passkey.createdAt(), passkey.lastUsedAt(),
                        passkey.backedUp()))
                .toList();
    }
}
