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

package com.irurueta.authserver.resourceserver.domain.orders;

import java.math.BigDecimal;

/**
 * Demo order.
 *
 * @param id    order identifier.
 * @param item  ordered item.
 * @param total order total.
 */
public record Order(String id, String item, BigDecimal total) {

    /**
     * Validates the order.
     *
     * @throws IllegalArgumentException if the id or the item is null or blank, or the total is null or negative.
     */
    public Order {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (item == null || item.isBlank()) {
            throw new IllegalArgumentException("item must not be blank");
        }
        if (total == null || total.signum() < 0) {
            throw new IllegalArgumentException("total must not be null or negative");
        }
    }
}
