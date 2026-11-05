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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigDecimal;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link Order}.
 */
class OrderTest {

    /** Identifier used by the tests. */
    private static final String ID = "1001";

    /** Item used by the tests. */
    private static final String ITEM = "Keyboard";

    /** Total used by the tests. */
    private static final BigDecimal TOTAL = new BigDecimal("49.90");

    /**
     * Verifies that a valid order keeps its values.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var order = new Order(ID, ITEM, TOTAL);

        assertEquals(ID, order.id());
        assertEquals(ITEM, order.item());
        assertEquals(TOTAL, order.total());
    }

    /**
     * Verifies that a zero total is accepted.
     */
    @Test
    void constructor_whenTotalIsZero_isAccepted() {
        assertEquals(BigDecimal.ZERO, new Order(ID, ITEM, BigDecimal.ZERO).total());
    }

    /**
     * Verifies that a null id is rejected.
     */
    @Test
    void constructor_whenIdIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new Order(null, ITEM, TOTAL));
    }

    /**
     * Verifies that a blank id is rejected.
     */
    @Test
    void constructor_whenIdIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new Order(" ", ITEM, TOTAL));
    }

    /**
     * Verifies that a null item is rejected.
     */
    @Test
    void constructor_whenItemIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new Order(ID, null, TOTAL));
    }

    /**
     * Verifies that a blank item is rejected.
     */
    @Test
    void constructor_whenItemIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new Order(ID, "", TOTAL));
    }

    /**
     * Verifies that a null total is rejected.
     */
    @Test
    void constructor_whenTotalIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new Order(ID, ITEM, null));
    }

    /**
     * Verifies that a negative total is rejected.
     */
    @Test
    void constructor_whenTotalIsNegative_throwsIllegalArgumentException() {
        final var negative = TOTAL.negate();

        assertThrows(IllegalArgumentException.class, () -> new Order(ID, ITEM, negative));
    }

    /**
     * Verifies the value semantics of the record.
     */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        assertEquals(new Order(ID, ITEM, TOTAL), new Order(ID, ITEM, TOTAL));
        assertEquals(new Order(ID, ITEM, TOTAL).hashCode(), new Order(ID, ITEM, TOTAL).hashCode());
        assertNotEquals(new Order(ID, ITEM, TOTAL), new Order("1002", ITEM, TOTAL));
    }
}
