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

package com.irurueta.authserver.resourceserver.api.web.orders;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.resourceserver.domain.orders.Order;
import java.math.BigDecimal;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link OrderResponse}.
 */
class OrderResponseTest {

    /** Total used by the test. */
    private static final BigDecimal TOTAL = new BigDecimal("49.90");

    /**
     * Verifies that every field of the order is copied.
     */
    @Test
    void from_whenOrderIsGiven_copiesItsFields() {
        final var response = OrderResponse.from(new Order("1001", "Keyboard", TOTAL));

        assertEquals(new OrderResponse("1001", "Keyboard", TOTAL), response);
    }
}
