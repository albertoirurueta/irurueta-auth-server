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

package com.irurueta.authserver.resourceserver.application.orders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.resourceserver.domain.orders.Order;
import com.irurueta.authserver.resourceserver.domain.orders.OrderRepository;
import java.math.BigDecimal;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ListOrdersUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ListOrdersUseCaseTest {

    /** Port that provides the orders. */
    @Mock
    private OrderRepository orderRepository;

    /**
     * Verifies that a null port is rejected.
     */
    @Test
    void constructor_whenRepositoryIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new ListOrdersUseCase(null));
    }

    /**
     * Verifies that the orders of the port are returned.
     */
    @Test
    void execute_whenRepositoryHasOrders_returnsThem() {
        final var orders = List.of(new Order("1001", "Keyboard", new BigDecimal("49.90")));
        when(orderRepository.findAll()).thenReturn(orders);

        final var result = new ListOrdersUseCase(orderRepository).execute();

        assertSame(orders, result);
        assertEquals(1, result.size());
    }

    /**
     * Verifies that an empty port yields an empty list.
     */
    @Test
    void execute_whenRepositoryIsEmpty_returnsAnEmptyList() {
        when(orderRepository.findAll()).thenReturn(List.of());

        assertTrue(new ListOrdersUseCase(orderRepository).execute().isEmpty());
    }
}
