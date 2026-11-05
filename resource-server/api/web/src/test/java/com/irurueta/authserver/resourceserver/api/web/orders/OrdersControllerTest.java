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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.resourceserver.application.orders.ListOrdersUseCase;
import com.irurueta.authserver.resourceserver.domain.orders.Order;
import java.math.BigDecimal;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link OrdersController}.
 */
@ExtendWith(MockitoExtension.class)
class OrdersControllerTest {

    /** Use case that lists the orders. */
    @Mock
    private ListOrdersUseCase listOrdersUseCase;

    /** Controller under test. */
    @InjectMocks
    private OrdersController controller;

    /**
     * Verifies that the orders of the use case are mapped onto response bodies.
     */
    @Test
    void orders_whenThereAreOrders_mapsThemToResponses() {
        final var total = new BigDecimal("49.90");
        when(listOrdersUseCase.execute()).thenReturn(List.of(new Order("1001", "Keyboard", total)));

        assertEquals(List.of(new OrderResponse("1001", "Keyboard", total)), controller.orders());
    }

    /**
     * Verifies that no orders yield an empty list.
     */
    @Test
    void orders_whenThereAreNoOrders_returnsAnEmptyList() {
        when(listOrdersUseCase.execute()).thenReturn(List.of());

        assertTrue(controller.orders().isEmpty());
    }
}
