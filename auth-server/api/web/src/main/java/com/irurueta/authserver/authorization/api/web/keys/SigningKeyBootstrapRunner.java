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

package com.irurueta.authserver.authorization.api.web.keys;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

// tag::keys-bootstrap[]
/**
 * Creates the first active and next keys at startup, so the server can sign tokens before the first scheduled
 * rotation.
 */
@Component
@RequiredArgsConstructor
public class SigningKeyBootstrapRunner implements ApplicationRunner {

    /** Rotates the keys. */
    private final SigningKeyRotator signingKeyRotator;

    /**
     * Runs the rotation once.
     *
     * @param args the application arguments.
     */
    @Override
    public void run(final ApplicationArguments args) {
        signingKeyRotator.rotate();
    }
}
// end::keys-bootstrap[]
