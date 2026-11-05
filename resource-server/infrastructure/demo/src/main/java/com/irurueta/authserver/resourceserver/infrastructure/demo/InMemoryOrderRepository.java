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

import com.irurueta.authserver.resourceserver.domain.orders.Order;
import com.irurueta.authserver.resourceserver.domain.orders.OrderRepository;
import java.math.BigDecimal;
import java.util.List;
import org.springframework.stereotype.Repository;

/**
 * {@link OrderRepository} that returns two hard-coded demo orders.
 */
@Repository
public class InMemoryOrderRepository implements OrderRepository {

    /** Orders returned by the repository. */
    private static final List<Order> ORDERS = List.of(
            new Order("1001", "Keyboard", new BigDecimal("49.90")),
            new Order("1002", "Monitor", new BigDecimal("189.00")));

    @Override
    public List<Order> findAll() {
        return ORDERS;
    }
}
