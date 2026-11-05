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

package com.irurueta.authserver.resourceserver;

import static org.junit.jupiter.api.Assertions.assertSame;
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
 * Unit tests of {@link BeanConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class BeanConfigurationTest {

    /** Port that provides the orders. */
    @Mock
    private OrderRepository orderRepository;

    /** Configuration under test. */
    private final BeanConfiguration configuration = new BeanConfiguration();

    /**
     * Verifies that the use case is wired to the given port.
     */
    @Test
    void listOrdersUseCase_whenCalled_wiresTheUseCaseToThePort() {
        final var orders = List.of(new Order("1001", "Keyboard", new BigDecimal("49.90")));
        when(orderRepository.findAll()).thenReturn(orders);

        final var useCase = configuration.listOrdersUseCase(orderRepository);

        assertSame(orders, useCase.execute());
    }
}
