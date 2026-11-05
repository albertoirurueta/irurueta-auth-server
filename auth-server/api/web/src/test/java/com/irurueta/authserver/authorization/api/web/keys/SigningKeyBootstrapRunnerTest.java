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

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.ApplicationArguments;

/**
 * Unit tests of {@link SigningKeyBootstrapRunner}.
 */
@ExtendWith(MockitoExtension.class)
class SigningKeyBootstrapRunnerTest {

    /** Rotates the keys. */
    @Mock
    private SigningKeyRotator signingKeyRotator;

    /** Subject under test. */
    @InjectMocks
    private SigningKeyBootstrapRunner runner;

    /**
     * Startup rotates once, which creates the first keys.
     */
    @Test
    void run_whenApplicationStarts_rotatesKeys() {
        runner.run(mock(ApplicationArguments.class));

        verify(signingKeyRotator).rotate();
    }
}
