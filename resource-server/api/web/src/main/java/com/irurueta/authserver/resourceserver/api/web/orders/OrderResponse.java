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

import com.irurueta.authserver.resourceserver.domain.orders.Order;
import io.swagger.v3.oas.annotations.media.Schema;
import java.math.BigDecimal;

/**
 * Body that describes an order.
 *
 * @param id    order identifier.
 * @param item  ordered item.
 * @param total order total.
 */
@Schema(description = "An order")
public record OrderResponse(
        @Schema(description = "Order identifier", example = "1001") String id,
        @Schema(description = "Ordered item", example = "Keyboard") String item,
        @Schema(description = "Order total", example = "49.90") BigDecimal total) {

    /**
     * Maps a domain order onto its web representation.
     *
     * @param order the order.
     * @return the response body.
     */
    public static OrderResponse from(final Order order) {
        return new OrderResponse(order.id(), order.item(), order.total());
    }
}
