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

import java.time.Duration;

/**
 * Waits between two polls of the token endpoint. It is a bean so that tests replace it and never really wait.
 */
@FunctionalInterface
public interface Sleeper {

    /**
     * Blocks the current thread for the given time.
     *
     * @param duration how long to wait.
     * @throws InterruptedException if the thread is interrupted while waiting.
     */
    void sleep(Duration duration) throws InterruptedException;
}
