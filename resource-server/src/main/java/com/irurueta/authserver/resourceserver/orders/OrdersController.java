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

package com.irurueta.authserver.resourceserver.orders;

import java.math.BigDecimal;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes demo orders.
 */
@RestController
public class OrdersController {

    // tag::resource-server-orders[]
    /**
     * Lists the demo orders.
     *
     * @return demo orders.
     */
    @GetMapping("/orders")
    public List<Order> orders() {
        return List.of(
                new Order("1001", "Keyboard", new BigDecimal("49.90")),
                new Order("1002", "Monitor", new BigDecimal("189.00")));
    }
    // end::resource-server-orders[]
}
