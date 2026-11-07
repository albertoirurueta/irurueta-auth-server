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

package com.irurueta.authserver.serviceclient.device;

import java.io.PrintStream;
import lombok.RequiredArgsConstructor;

/**
 * Writes the lines a person (or a test) reads. Lines always end with {@code \n}, never with the platform's line
 * separator.
 */
@RequiredArgsConstructor
public class DeviceFlowOutput {

    /** The stream. */
    private final PrintStream stream;

    /**
     * Writes one line and flushes it, so that it is visible while the CLI keeps polling.
     *
     * @param text the line, without terminator.
     */
    public void line(final String text) {
        stream.print(text);
        stream.print('\n');
        stream.flush();
    }
}
