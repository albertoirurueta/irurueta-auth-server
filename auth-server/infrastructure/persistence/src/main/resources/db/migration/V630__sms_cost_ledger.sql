-- Copyright (C) 2026 Alberto Irurueta Carro (alberto@irurueta.com)
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--         http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- tag::sms-cost-ledger-schema[]
CREATE TABLE sms_cost_ledger
(
    id         bigint GENERATED ALWAYS AS IDENTITY,
    sent_at    timestamp with time zone NOT NULL,
    country    char(2)                  NOT NULL,
    cost_micros bigint                  NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT ck_sms_cost_ledger_cost CHECK (cost_micros >= 0)
);

CREATE INDEX ix_sms_cost_ledger_sent_at ON sms_cost_ledger (sent_at);
-- end::sms-cost-ledger-schema[]
