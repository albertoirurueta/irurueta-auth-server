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

import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordCheck;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;

/**
 * Adapter of the {@link CompromisedPasswordCheck} port over Spring Security's {@link CompromisedPasswordChecker}
 * (in production, the Have I Been Pwned range API, which only receives a hash prefix of the password).
 */
@RequiredArgsConstructor
public class SpringCompromisedPasswordCheck implements CompromisedPasswordCheck {

    /** Checker that does the work. */
    private final CompromisedPasswordChecker checker;

    @Override
    public boolean isCompromised(final String password) {
        return checker.check(password).isCompromised();
    }
}
