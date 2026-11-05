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

import com.irurueta.authserver.resourceserver.domain.orders.Order;
import com.irurueta.authserver.resourceserver.domain.orders.OrderRepository;
import java.util.List;

/**
 * Use case that lists the orders. A plain class (final, so that a constructor that rejects its argument cannot
 * leave a partially initialized subclass behind): the {@code boot} module registers it as a bean.
 */
public final class ListOrdersUseCase {

    /** Port that provides the orders. */
    private final OrderRepository orderRepository;

    /**
     * Creates the use case.
     *
     * @param orderRepository port that provides the orders.
     * @throws IllegalArgumentException if the port is null.
     */
    public ListOrdersUseCase(final OrderRepository orderRepository) {
        if (orderRepository == null) {
            throw new IllegalArgumentException("orderRepository must not be null");
        }
        this.orderRepository = orderRepository;
    }

    /**
     * Lists the orders.
     *
     * @return the orders, or an empty list when there are none.
     */
    public List<Order> execute() {
        return orderRepository.findAll();
    }
}
