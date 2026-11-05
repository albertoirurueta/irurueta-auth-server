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

import com.irurueta.authserver.resourceserver.application.orders.ListOrdersUseCase;
import com.irurueta.authserver.resourceserver.domain.orders.OrderRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Composition root: registers the use cases, which are plain classes, as beans wired to their ports.
 */
@Configuration(proxyBeanMethods = false)
public class BeanConfiguration {

    /**
     * Creates the use case that lists the orders.
     *
     * @param orderRepository port that provides the orders.
     * @return the use case.
     */
    @Bean
    public ListOrdersUseCase listOrdersUseCase(final OrderRepository orderRepository) {
        return new ListOrdersUseCase(orderRepository);
    }
}
