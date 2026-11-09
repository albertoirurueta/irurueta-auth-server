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

package com.irurueta.authserver.authorization.application.keys;

import com.irurueta.authserver.authorization.application.account.RegisterAccountUseCase;
import com.irurueta.authserver.authorization.domain.keys.SignedTokenLifetimes;
import java.time.Duration;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Decides how long a retired signing key stays published. A key must be published for as long as any token it signed
 * can still be presented, so the effective retention is the longest of the configured retention and the longest
 * signed-token lifetime plus the allowed clock skew. The signed tokens are the access and ID tokens of the
 * registered clients (reported by the {@link SignedTokenLifetimes} port) and the e-mail verification tokens.
 */
@Service
@RequiredArgsConstructor
public class SigningKeyRetention {

    /** Port that reports the lifetimes of the tokens the clients obtain. */
    private final SignedTokenLifetimes signedTokenLifetimes;

    /** Minimum retention ({@code authserver.keys.retention}, set in {@code application.yml}). */
    @Value("${authserver.keys.retention}")
    private final Duration configuredRetention;

    /** Clock skew tolerated by the token consumers ({@code authserver.keys.clock-skew} in {@code application.yml}). */
    @Value("${authserver.keys.clock-skew}")
    private final Duration clockSkew;

    // tag::keys-retention[]
    /**
     * Computes the effective retention at this moment: registering a client with longer-lived tokens lengthens it.
     *
     * @return the longest of the configured retention and the longest signed-token lifetime plus the clock skew.
     */
    public Duration effective() {
        final var longestToken = Stream.of(signedTokenLifetimes.longest(), RegisterAccountUseCase.VERIFICATION_TTL)
                .max(Duration::compareTo).orElseThrow();
        final var needed = longestToken.plus(clockSkew);
        return needed.compareTo(configuredRetention) > 0 ? needed : configuredRetention;
    }
    // end::keys-retention[]
}
