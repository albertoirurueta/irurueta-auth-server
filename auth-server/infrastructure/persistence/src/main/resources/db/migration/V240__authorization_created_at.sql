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


-- tag::tokens-authorization-created[]
-- When each authorization row was created. Spring Authorization Server lists its columns explicitly, so the default
-- fills it in. An authorization that never got a token (an authorization or consent request the user abandoned) has
-- no expiry at all; the clean-up job deletes it once it is older than a configurable threshold.
ALTER TABLE oauth2_authorization
    ADD COLUMN created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP;
-- end::tokens-authorization-created[]
