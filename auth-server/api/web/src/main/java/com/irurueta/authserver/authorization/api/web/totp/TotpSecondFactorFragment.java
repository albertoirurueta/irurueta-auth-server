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

package com.irurueta.authserver.authorization.api.web.totp;

import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorFragment;
import org.springframework.stereotype.Component;

/**
 * Contributes the forms of the TOTP code and of the recovery code to the second-factor page, as every second factor
 * does through the {@link SecondFactorFragment} extension point.
 */
@Component
public class TotpSecondFactorFragment implements SecondFactorFragment {

    /** Position of the TOTP forms in the second-factor page. */
    public static final int ORDER = 100;

    @Override
    public String templateName() {
        return "totp";
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
