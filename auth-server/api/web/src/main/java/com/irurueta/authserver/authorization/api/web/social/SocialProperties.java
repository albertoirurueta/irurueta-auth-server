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

package com.irurueta.authserver.authorization.api.web.social;

import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import com.irurueta.authserver.authorization.domain.social.ProviderTrust;
import java.time.Duration;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.StringUtils;

// tag::social-properties[]
/**
 * Settings of the sign-in with external providers, bound once from {@code authserver.social.*} and injected wherever
 * one is needed; an invalid value stops the application at startup. A provider is enabled when its
 * {@code client-id} has text: a blank one leaves the provider off, so the shipped {@code application.yml} can list all
 * of them with the values of environment variables and nothing is enabled until a deployment supplies them. Secrets
 * (the client secret, the Apple private key) are never kept in a committed file: they come from the environment only.
 *
 * <p>Whether a provider's own multi-factor authentication is trusted ({@code trust-mfa}) is per provider and off by
 * default: the sign-in is then a primary factor and the normal second-factor flow applies.
 *
 * @param providers settings of each provider, by registration id ({@code google}, {@code microsoft}, {@code apple},
 *                  {@code github}).
 */
@ConfigurationProperties("authserver.social")
public record SocialProperties(Map<String, Provider> providers) {

    /** Tenant value of Entra ID that accepts work, school and personal accounts of any tenant. */
    public static final String COMMON_TENANT = "common";

    /** Tenant value of Entra ID that accepts work and school accounts of any tenant. */
    public static final String ORGANIZATIONS_TENANT = "organizations";

    /** Tenant value of Entra ID that accepts personal accounts only. */
    public static final String CONSUMERS_TENANT = "consumers";

    /** Longest lifetime Apple accepts for a client secret: six months. */
    public static final Duration MAX_APPLE_CLIENT_SECRET_TTL = Duration.ofDays(180);

    /** Default lifetime of the client secret JWT sent to Apple. */
    public static final Duration DEFAULT_APPLE_CLIENT_SECRET_TTL = Duration.ofMinutes(5);

    /** Shape of a tenant id (a GUID): the issuer of a single-tenant token is built from it. */
    private static final Pattern TENANT_ID_PATTERN = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    /** Characters a tenant (a GUID or a domain name) may contain: it becomes part of a URL. */
    private static final Pattern TENANT_PATTERN = Pattern.compile("[A-Za-z0-9][A-Za-z0-9.-]*");

    /**
     * Validates the settings and copies the map.
     *
     * @throws IllegalArgumentException if a key is not the registration id of a known provider, or an enabled provider
     *                                  lacks a setting it needs or has an invalid one.
     */
    public SocialProperties {
        final var copy = new LinkedHashMap<String, Provider>();
        if (providers != null) {
            providers.forEach((id, provider) -> {
                final var known = IdentityProvider.fromId(id).orElseThrow(() -> new IllegalArgumentException(
                        "authserver.social.providers." + id + " is not a known provider"));
                if (provider != null) {
                    validate(known, provider);
                    copy.put(id, provider);
                }
            });
        }
        providers = Map.copyOf(copy);
    }

    /**
     * Returns the enabled providers, in the order of {@link IdentityProvider}.
     *
     * @return the enabled providers and their settings; empty when none is configured.
     */
    public Map<IdentityProvider, Provider> enabledProviders() {
        final var enabled = new EnumMap<IdentityProvider, Provider>(IdentityProvider.class);
        providers.forEach((id, provider) -> {
            if (provider.enabled()) {
                IdentityProvider.fromId(id).ifPresent(known -> enabled.put(known, provider));
            }
        });
        return enabled;
    }

    /**
     * Returns the settings of an enabled provider.
     *
     * @param provider the provider.
     * @return its settings, or an empty optional when it is not enabled.
     */
    public Optional<Provider> find(final IdentityProvider provider) {
        return Optional.ofNullable(enabledProviders().get(provider));
    }

    /**
     * Returns how far the multi-factor authentication of a provider is trusted.
     *
     * @param provider the provider.
     * @return the trust setting; the provider is not trusted when it is not enabled.
     */
    public ProviderTrust trust(final IdentityProvider provider) {
        return new ProviderTrust(provider, find(provider).map(Provider::trustMfa).orElse(false));
    }

    /**
     * Checks the settings of a provider that is enabled.
     *
     * @param id       the provider.
     * @param provider its settings.
     */
    private static void validate(final IdentityProvider id, final Provider provider) {
        if (!provider.enabled()) {
            return;
        }
        final var prefix = "authserver.social.providers." + id.id() + ".";
        if (id == IdentityProvider.APPLE) {
            require(provider.teamId(), prefix + "team-id");
            require(provider.keyId(), prefix + "key-id");
            require(provider.privateKey(), prefix + "private-key");
            if (provider.clientSecretTtl().isNegative() || provider.clientSecretTtl().isZero()
                    || provider.clientSecretTtl().compareTo(MAX_APPLE_CLIENT_SECRET_TTL) > 0) {
                throw new IllegalArgumentException(
                        prefix + "client-secret-ttl must be positive and at most " + MAX_APPLE_CLIENT_SECRET_TTL);
            }
        } else {
            require(provider.clientSecret(), prefix + "client-secret");
        }
        if (id == IdentityProvider.MICROSOFT) {
            if (!TENANT_PATTERN.matcher(provider.tenant()).matches()) {
                throw new IllegalArgumentException(prefix + "tenant is not a valid tenant");
            }
            if (provider.allowedTenants().stream().anyMatch(tenant -> !TENANT_PATTERN.matcher(tenant).matches())) {
                throw new IllegalArgumentException(prefix + "allowed-tenants holds a value that is not a valid tenant");
            }
        }
    }

    /**
     * Requires a setting to have text.
     *
     * @param value value of the setting.
     * @param name  full name of the setting, for the message.
     */
    private static void require(final String value, final String name) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(name + " must not be blank when the provider is enabled");
        }
    }

    /**
     * Settings of one provider. Only the ones that apply to the provider are read: the client secret by Google,
     * Microsoft and GitHub, the tenant settings by Microsoft and the key settings by Apple (whose client secret is a
     * JWT signed with the private key).
     *
     * @param clientId        client id registered with the provider; blank leaves the provider disabled.
     * @param clientSecret    client secret (Google, Microsoft, GitHub), supplied from the environment.
     * @param trustMfa        whether the provider's {@code amr} claim is trusted to prove several factors (default
     *                        {@code false}).
     * @param tenant          Entra ID tenant: {@code common} (the default), {@code organizations},
     *                        {@code consumers}, or a tenant id or domain.
     * @param allowedTenants  tenant ids an Entra ID multi-tenant sign-in is limited to; empty accepts any tenant.
     * @param teamId          Apple developer team id.
     * @param keyId           id of the Apple key the client secret is signed with.
     * @param privateKey      PKCS#8 PEM private key (ES256) Apple issued, supplied from the environment; a literal
     *                        {@code \n} stands for a line break.
     * @param clientSecretTtl lifetime of the client secret JWT sent to Apple (default five minutes, at most six
     *                        months).
     */
    public record Provider(
            String clientId,
            String clientSecret,
            boolean trustMfa,
            @DefaultValue(COMMON_TENANT) String tenant,
            List<String> allowedTenants,
            String teamId,
            String keyId,
            String privateKey,
            @DefaultValue("PT5M") Duration clientSecretTtl) {

        /**
         * Copies the tenants and fills the defaults of the unbound settings.
         */
        public Provider {
            allowedTenants = allowedTenants == null ? List.of() : List.copyOf(allowedTenants);
            tenant = StringUtils.hasText(tenant) ? tenant : COMMON_TENANT;
            clientSecretTtl = clientSecretTtl == null ? DEFAULT_APPLE_CLIENT_SECRET_TTL : clientSecretTtl;
        }

        /**
         * Returns the tenants an Entra ID sign-in is limited to: the configured list, else the tenant itself when it is
         * a tenant id, else none, which means any tenant (a multi-tenant application, or a tenant given by domain
         * name, whose tokens carry its id).
         *
         * @return the permitted tenant ids; empty accepts any tenant.
         */
        public List<String> permittedTenants() {
            if (!allowedTenants.isEmpty()) {
                return allowedTenants;
            }
            return TENANT_ID_PATTERN.matcher(tenant).matches() ? List.of(tenant) : List.of();
        }

        /**
         * Tells whether the provider is enabled.
         *
         * @return {@code true} when the client id has text.
         */
        public boolean enabled() {
            return StringUtils.hasText(clientId);
        }
    }
}
// end::social-properties[]
