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

package com.irurueta.authserver.authorization;

import com.irurueta.authserver.testsupport.PostgresIT;
import org.junit.jupiter.api.Test;

/**
 * Starts the whole application against a PostgreSQL container.
 */
@PostgresIT
class AuthServerApplicationIT {

    /**
     * Fails if the application context cannot start.
     */
    @Test
    void contextLoads_whenApplicationStarts_succeeds() {
        // the context is started by the test framework; reaching this point is the assertion
    }
}
