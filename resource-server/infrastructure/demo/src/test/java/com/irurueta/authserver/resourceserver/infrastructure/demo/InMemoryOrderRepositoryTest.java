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

package com.irurueta.authserver.resourceserver.infrastructure.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigDecimal;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link InMemoryOrderRepository}.
 */
class InMemoryOrderRepositoryTest {

    /** Number of demo orders. */
    private static final int ORDER_COUNT = 2;

    /** Repository under test. */
    private final InMemoryOrderRepository repository = new InMemoryOrderRepository();

    /**
     * Verifies that the two demo orders are returned.
     */
    @Test
    void findAll_whenCalled_returnsTheTwoDemoOrders() {
        final var orders = repository.findAll();

        assertEquals(ORDER_COUNT, orders.size());
        assertEquals("1001", orders.getFirst().id());
        assertEquals("Keyboard", orders.getFirst().item());
        assertEquals(new BigDecimal("49.90"), orders.getFirst().total());
        assertEquals("1002", orders.getLast().id());
        assertEquals("Monitor", orders.getLast().item());
        assertEquals(new BigDecimal("189.00"), orders.getLast().total());
    }
}
