# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. Follow these
rules over any general-purpose default. Where a rule below and a generated scaffold disagree, this file wins.

## What this is

An **example** OAuth 2.1 / OpenID Connect authorization server built from scratch with Spring Boot 4.1 and Spring
Security 7.1 (Spring Authorization Server), plus the applications that use it. It backs the step-by-step guide
*Building an Authorization Server from Scratch* in the docs site (repository `albertoirurueta/docs`, under
`modules/ROOT/pages/backend/springboot/authorization-server-from-scratch/`), which includes code from this repository
with tagged regions. The applications are never deployed: CI only builds, analyses and tests them, and publishes the
documentation (Antora site plus Maven site reports) to GitHub Pages.

## Commands

Requires JDK 21–25 (the build enforces `[21,26)`; SpotBugs cannot parse JDK 26+ class files) and Docker for
Testcontainers.

```bash
./mvnw -B clean verify                 # unit (*Test) + integration (*IT) tests and every build gate (must be green)
./mvnw test                            # fast unit-test run only, no Spring context starts
./mvnw -pl auth-server/api/web -am test -Dtest=LoginControllerTest   # one test class in one module
./mvnw -pl auth-server/boot -am spring-boot:run -Dspring-boot.run.profiles=dev   # run one application
./mvnw install && ./mvnw site site:stage -DskipTests   # browsable reports, staged as published under /mvn-site
cd docs && npm ci && npx antora antora-playbook.yml            # build this repository's Antora docs
```

Ports: auth-server 9000, bff 8080, resource-server 8081.

## Architecture

Hexagonal, one Maven sub-reactor per application, enforced twice: by `maven-enforcer-plugin` `bannedDependencies` in
each module's pom (jar granularity) and by a `HexagonalArchitectureTest` (ArchUnit) in each application's `boot`
module (package granularity). Never weaken either to make code fit; move the code instead.

```
<app>/                          aggregator pom (packaging pom), artifactId <app>-parent
  domain/                       <app>-domain
  application/                  <app>-application
  infrastructure/<adapter>/     <app>-infrastructure-<adapter>   (driven adapters: persistence, keys, ...)
  api/<adapter>/                <app>-api-<adapter>              (driving adapters: web, ...)
  boot/                         <app>-boot                       (composition root, the only runnable artifact)
```

| Module | May depend on | Must not contain |
|---|---|---|
| `domain` | nothing but the JDK (and Lombok, compile-only) | Spring, Jackson, JPA/JDBC, Spring Security types: the only framework-free module |
| `application` | `domain`, Spring | Spring Security types; use cases are `@Service` beans found by component scanning |
| `infrastructure/*` | `domain`, `application` | a sibling adapter, any `api/*` module |
| `api/*` | `domain`, `application` | any `infrastructure/*` module; a mapping annotation of its own (controllers implement generated interfaces, see *API contracts*) |
| `boot` | everything | business logic: it only wires beans, holds `application*.yml` and the integration tests |

- Package roots: `com.irurueta.authserver.authorization` (auth-server), `com.irurueta.authserver.bff`,
  `com.irurueta.authserver.resourceserver`, `com.irurueta.authserver.serviceclient`. Below each root the module
  name is the next package segment (`…authorization.domain`, `…authorization.application`,
  `…authorization.infrastructure.persistence`, `…authorization.api.web`); the `*Application` class lives in the
  root package inside `boot`, so component scanning covers every module.
- A port is an interface in `domain` (named for what it provides, for example `UserAccountRepository`); its
  implementation lives in an `infrastructure/*` adapter. A port implementation never returns `null` (an empty
  `Optional`/`List` instead) and never lets a JDBC, HTTP or framework type escape through it.
- **Domain models are never returned from a controller**; map them onto the DTO generated from the
  contract (or, for an api adapter without a contract, a record in the adapter). The mapper belongs to the adapter,
  never to `domain`.
- Spring Security and Spring Authorization Server types (`UserDetailsService`, `RegisteredClientRepository`,
  `SecurityFilterChain`, …) are framework adapters: they live in `api/*` or `infrastructure/*`, never in `domain`
  or `application`.
- A layer is only created once it has code: an application with no driven adapter or no use case yet has no
  `infrastructure` or `application` module, so `service-client` stays a single `boot` module until #8 gives it a
  domain. `auth-server` has `infrastructure/persistence`, `infrastructure/keys` and `infrastructure/mail`;
  `resource-server` has `domain`, `application`, `infrastructure/memory`, `api/web` and `boot`; `bff` has `domain`,
  `application`, `infrastructure/session`, `infrastructure/resourceserver`, `api/web` and `boot`.
- **No demo-only code in `src/main`.** The applications are meant to be reusable and deployable: an endpoint, entity
  or adapter that exists only so a test has something to call lives in `src/test`. The only exceptions are
  `DevDataInitializer` in `infrastructure/persistence` and `DevKeyEncryptionSecret` in `infrastructure/keys` of
  `auth-server`, and `BffDevDatabase` in `bff/infrastructure/session` (all `dev`-profile only, inert elsewhere, and
  their Javadoc says why they cannot live in `src/test`: the end-to-end tests run the packaged jar).
- `test-support` (shared Testcontainers base), `e2e-tests` and `coverage` (JaCoCo aggregate) are root modules
  outside the applications.

### Feature layout inside `auth-server`

A feature (an authentication method or capability) spans the layers with **the same package name in each**, so it
can be developed in parallel without editing shared files: `…domain.<feature>`, `…application.<feature>`,
`…infrastructure.persistence.<feature>`, `…api.web.<feature>`. Feature names: `password`, `keys`, `tokens`,
`clients`, `login`, `mfa`, `totp`, `passkeys`, `ott`, `social`, `x509`, `implicit`, `account`, `admin`. Each
placeholder package holds a `package-info.java` saying which issue fills it.

### Extension points: adding a login method without editing shared files

- `api.web.login.LoginChainCustomizer` (a functional interface over `HttpSecurity`, deliberately **not** a `Customizer<HttpSecurity>`, because Spring Security applies every such bean to every filter chain): every bean of this type is applied, in
  `@Order`, to the login/UI chain by `SecurityConfig`, **before** its catch-all `anyRequest().authenticated()`, so a
  customizer may still permit its own endpoints. A new method declares one in its own `@Configuration` to enable its
  `HttpSecurity` features (for example `http.oneTimeTokenLogin(...)`); `SecurityConfig` is never edited.
- `api.web.login.LoginMethodFragment`: every bean of this type contributes a Thymeleaf fragment (`templateName()`,
  `fragmentName()`, `order()`; `reference()` builds the `template :: fragment` expression) that `LoginController`
  passes to `templates/login.html`, which renders them below the password form.

- `api.web.ProtocolChainCustomizer` (a functional interface over `OAuth2AuthorizationServerConfigurer`, deliberately **not** a `Customizer<...>` bean type for the same reason): every bean of this type is
  applied, in `@Order`, to the protocol chain (`/oauth2/**`, `/.well-known/**`, OIDC endpoints) by
  `SecurityConfig.authorizationServerSecurityFilterChain`, right after OIDC is enabled. A feature declares one in its
  own `@Configuration` to add a converter or provider to a protocol endpoint (for example `x509` or `implicit`);
  `SecurityConfig` is never edited.
- `api.web.tokens.JwtClaimsContributor` (introduced by the token customisation task): every bean of this type adds
  claims, through `IssuedTokenClaims`, to the access tokens of both formats and to the ID tokens:
  `RolesTenantAudienceTokenCustomizer` (the one `OAuth2TokenCustomizer<JwtEncodingContext>`) applies it to the JWTs and
  `ReferenceTokenClaimsCustomizer` (the one `OAuth2TokenCustomizer<OAuth2TokenClaimsContext>`) to the reference tokens,
  so a feature (for example `mfa` adding `amr`) contributes claims without owning a customizer. A contributor checks
  `context.getTokenType()` when a claim belongs to one kind of token only.
- `api.web.ApiSecurityConfig`: the stateless `/api/**` chain (`@Order(0)`, errors per RFC 6750) with a decoder of its
  own over the published keys: issuer, timestamps, `aud` containing `authserver.api.audience` (default `auth-server`),
  and no `purpose` claim. Never make that decoder the framework-wide `JwtDecoder` bean, which the UserInfo endpoint
  uses for tokens of other audiences. Its public paths and the `/api/admin/**` rule (scope `admin` only) are fixed
  there; a feature only adds controllers under `/api/**`.
- `api.web.SchedulingConfiguration` enables `@Scheduled` once for every feature; a feature declares its job (a
  `@Component` with a `@Scheduled` method calling a use case) and never enables scheduling itself.

A later issue therefore adds a login method by creating its feature packages (domain model and port, use case,
persistence adapter, web `@Configuration` with its controller, a `templates/<method>.html`, a `LoginChainCustomizer`
bean and a `LoginMethodFragment` bean), plus its own Flyway migration in its range. No existing file needs to change.

### Flyway ranges

Migrations live in `auth-server/infrastructure/persistence/src/main/resources/db/migration`
(`classpath:db/migration`). The skeleton (#1) uses `V100`–`V199` (`V100` Spring Authorization Server schema, `V101`
users). Used so far: `V200` account, `V210` signing keys, `V230` consumed refresh tokens. Each issue states its own
range in its body; never write a migration outside it. The `bff` has its own database (`bff`) and its own Flyway
history: `V300` (Spring Session schema) lives in `bff/infrastructure/session/src/main/resources/db/migration`.

### Key encryption secret

- Private signing keys are encrypted at rest from `authserver.keys.encryption.password` and `.salt` (hex). With the
  `dev` profile `DevKeyEncryptionSecret` generates them once per machine under `~/.irurueta-auth-server/` (owner-only
  file, never inside the repository). Without `dev` they must be supplied, normally through the environment variables
  `AUTHSERVER_KEYS_ENCRYPTION_PASSWORD` and `AUTHSERVER_KEYS_ENCRYPTION_SALT`; tests pass runtime-generated values.

### API contracts

**Every HTTP endpoint the application itself handles, JSON or HTML page, is defined first in an OpenAPI contract
under `apis/<app>/`, and its controller only implements the interface openapi-generator produces. Never put a mapping
annotation (`@RequestMapping`, `@GetMapping`, `@PostMapping`, `@PutMapping`, `@PatchMapping`, `@DeleteMapping`) in
hand-written code.** The contracts are the source of truth (see `apis/README.md`).

- **JSON endpoints**: `apis/<app>/rest-server/<app>-api-v1.yaml`. Add the operation (every operation, parameter,
  schema and property described, every constraint expressed), regenerate
  (`./mvnw -pl <app>/api/web -am generate-sources`) and implement the generated interface in a controller that calls
  use cases. openapi-generator (`spring`, `interfaceOnly`, records, Spring Boot 4, Jackson 3, Bean Validation)
  generates the interfaces and DTOs into each `api/web` module's `target/generated-sources` (packages
  `…api.web.v1.generated.{api,model}`). Never hand-write a web DTO: a `@Component` mapper per feature (for example
  `ClientDtoMapper`) in the api adapter converts between generated DTOs and the domain; problem details go through
  `ProblemJsonExceptionHandler` or the feature's scoped `@RestControllerAdvice`.
- **HTML pages**: `apis/<app>/web-pages/<app>-pages-v1.yaml` (today `auth-server-pages-v1.yaml`: `/login`,
  `/oauth2/consent`, `/logout`), generated into `…api.web.pages.v1.generated.api`. Each operation answers
  `text/html`; its controller renders the Thymeleaf template with `PageRenderer` (`api.web.pages`), which resolves the
  view with the request's locale, renders it against the current request (CSRF fields, `@{}` links and messages keep
  working) and adds the branding. The pages are published by the springdoc group `pages` (`/v3/api-docs/pages`) and
  compared with their contract by `OpenApiDriftIT`.
- **Calls to another service** go through a client generated from that service's contract (`java` generator,
  `library=restclient`, into `…infrastructure.<adapter>.v1.generated`), behind a domain port implemented in an
  `infrastructure/*` adapter that translates every failure into a domain exception (for example
  `RestDocumentGateway` in `bff/infrastructure/resourceserver`). There is no generic pass-through relay: every
  operation an application exposes is in its own contract.
- **Exempt** are only the endpoints owned by frameworks: the Spring Security filters (`POST /login`, `POST /logout`,
  `POST /bff/logout`, `/oauth2/**`, `/login/oauth2/**`), the Spring Authorization Server protocol endpoints
  (`/oauth2/**`, `/.well-known/**`, `/connect/**`, `/userinfo`), Spring Boot's `BasicErrorController` (`/error`,
  customised only through an `ErrorViewResolver` bean) and actuator.
- Generated code is never committed or edited, and is excluded from Checkstyle, PMD/CPD, SpotBugs, JaCoCo and Sonar.
- **Enforced**: `HexagonalArchitectureTest` in each application's `boot` module fails when a hand-written class or
  method (outside a `..generated..` package) carries a mapping annotation, or a `@Controller`/`@RestController` does
  not implement an interface from a `..generated.api..` package; `OpenApiDriftIT` fails when a document springdoc
  serves differs from its contract.

## Conventions

- Every source file starts with the Apache 2.0 header used in the existing files.
- Never commit secrets, keys or certificates: generate dev keys at first start and test keys inside the tests.
- Code shown in the docs guide is wrapped in tag comments, see below. Never rename or remove a tag without updating
  the docs repository.
- A new endpoint, JSON or HTML page, and a call to another service start in a contract under `apis/` (see *API
  contracts* above); a mapping annotation in hand-written code fails the build.

### Tag-comment convention

Code included by the docs guide is wrapped in `tag::<feature>-<what>[]` / `end::<feature>-<what>[]` markers
(lowercase kebab-case, feature first, for example `security-chains`, `login-form`, `sas-schema`, `bff-user`). The
comment syntax follows the file type: `// tag::x[]` in Java, `-- tag::x[]` in SQL, `# tag::x[]` in YAML/properties and
`<!-- tag::x[] -->` in HTML/XML. Antora includes them with
`include::irurueta-auth-server::example$<module-path>/src/...[tag=x]`, where `<module-path>` is the module's directory
from the repository root (for example `auth-server/api/web`). The Antora Collector copies each module's `src/**`
(plus the root `pom.xml` and `compose.yaml`) into the `example$` family; `docs/antora.yml` holds one scan per module,
so a new module needs a new scan there.

## Testing

### Assertions: JUnit, not AssertJ

Use `org.junit.jupiter.api.Assertions` only. Do **not** add AssertJ to a test unless something genuinely cannot be
expressed without it, and say why in the test's javadoc if you do.

```java
// Yes
assertEquals(expected, actual);
assertSame(expected, actual);
assertTrue(result.isEmpty());
final var error = assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername("x"));
assertTrue(error.getMessage().contains("x"));

// No
assertThat(actual).isEqualTo(expected);
assertThatThrownBy(() -> service.loadUserByUsername("x")).isInstanceOf(UsernameNotFoundException.class);
```

MockMvc's own `andExpect(...)` matchers and Hamcrest matchers passed to them are fine: they are MockMvc's API, not an
assertion library.

### Test doubles: Mockito, never hand-written fakes

Do **not** write `Fake*`/`Stub*` classes or anonymous implementations of a port or interface in a test. Use Mockito
mocks or spies.

```java
@ExtendWith(MockitoExtension.class)
class FindUserAccountUseCaseTest {

    @Mock
    private UserAccountRepository userAccountRepository;

    @InjectMocks
    private FindUserAccountUseCase useCase;
```

- Prefer `@InjectMocks` over a `@BeforeEach` that news up the subject by hand.
- Use an `ArgumentCaptor` when a test needs to prove the *same instance* was passed through: records have value
  equality, so `verify(port).method(query)` alone does not prove identity.
- Build a captor with `ArgumentCaptor.captor()`, never `ArgumentCaptor.forClass(...)`, which yields a raw type for
  generic arguments: `final var captor = ArgumentCaptor.<List<UUID>>captor();`. A `@Captor` field is fine too.
- Spring test slices replace beans with `@MockitoBean`, never with a hand-written `@TestConfiguration` double.
  Real in-memory framework implementations used as *test data* (for example an `InMemoryRegisteredClientRepository`
  holding one client for a slice test) are not doubles of this repository's own ports and are allowed.

### Test method naming

```
void methodBeingTested_whenCondition_expectedResult()
```

```java
void loadUserByUsername_whenUserIsMissing_throwsUsernameNotFoundException()
void constructor_whenUsernameIsBlank_throwsIllegalArgumentException()
void loginSecurityFilterChain_whenCustomizerPermitsPath_doesNotRedirectToLogin()
void equalsAndHashCode_whenFieldsMatch_areEqual()
```

- For a record's canonical constructor use `constructor`; for a static factory use its own name; for value
  semantics use `equalsAndHashCode`; for an HTTP endpoint test name the handler method or the path segment.
- Checkstyle's `MethodName` check forbids underscores, so `checkstyle.xml` carries a `SuppressionSingleFilter` scoped
  to `.*(Test|IT)\.java$`. Production method names stay camelCase; do not widen that suppression.

### Test class layout

- **One test class per production class.** Do not group several production classes into one test class.
- **Order methods public → private.** Fields and setup first, then `@Test` methods, then private helpers last.
- **Nested types go last** (see *Member order* under Java style). A nested configuration class of a test stays
  package-private: the test class's own `@Import` cannot name a private nested class, and Spring's test context
  only detects non-private nested configuration classes. Say so in its Javadoc.

### Unit tests are `*Test`, integration tests are `*IT`

| Plugin | Includes | Phase | What belongs there |
|---|---|---|---|
| Surefire | `**/*Test.java` | `test` | Unit tests: no Spring application context, no Docker |
| Failsafe | `**/*IT.java` | `verify` | Integration tests: a Spring context, Testcontainers or the packaged jars |

**Any class carrying `@SpringBootTest` or a Spring test slice (`@WebMvcTest`, `@JdbcTest`, `@DataJdbcTest`, …), or
starting a container, is an integration test: name it `*IT.java`, never `*Test.java`.** `mvn test` must stay a fast
unit-test run; `mvn verify` runs both. JaCoCo's `prepare-agent-integration` writes `jacoco-it.exec` and the
`coverage` module merges every `jacoco*.exec`, so moving a test to `*IT` does not drop its coverage out of the gate.

### Shared test infrastructure

- `test-support` holds `OpenApiContract`, `PostgresTestConfiguration` (a `postgres:18` Testcontainers container exposed through
  `@ServiceConnection`) and the `@PostgresIT` meta-annotation: `@SpringBootTest` wired to that container, with a
  `webEnvironment()` attribute for `RANDOM_PORT` tests. Consumers depend on it with `<scope>test</scope>`.
- `e2e-tests` drives the packaged `auth-server` and `bff` boot jars through headless Chromium with Playwright for
  Java (chosen over Selenium because it manages its own browser binaries, auto-waits for elements and needs no
  driver setup). It must stay last in the reactor, before `coverage`.
- `OpenApiContract` (test-support) summarizes an OpenAPI contract and a served document; `OpenApiDriftIT` in each
  `boot` module compares `apis/<app>/rest-server/<app>-api-v1.yaml` with `/v3/api-docs` and, in `auth-server`,
  `apis/auth-server/web-pages/auth-server-pages-v1.yaml` with `/v3/api-docs/pages` (operations, status codes,
  parameters, bodies, security, schemas). To change an API or a page, edit the contract; there is nothing else to
  regenerate or commit. springdoc only documents its groups (see each `OpenApiConfig`): `api` (`/api/**` in
  `auth-server` and `resource-server`, `/bff/**` and `/api/**` in `bff`) and, in `auth-server`, `pages` (`/login`,
  `/oauth2/consent`, `/logout`). Put every new endpoint under one of them, or widen the group.
- The `dev` profile of `auth-server` resolves `../../compose.yaml` against the working directory (`spring-boot:run`
  uses the `boot` module directory); elsewhere, set `SPRING_DOCKER_COMPOSE_FILE` to the root `compose.yaml`.

## Java style

- **Member order** (the Java Code Conventions order, plus nested types last as IntelliJ's default arrangement and
  most style guides do): static fields, instance fields, constructors, methods (public → private), then nested
  types. A nested type is `private` unless code outside the enclosing class, or a framework that requires it,
  needs to see it.
- **Records** for immutable types (domain models, value objects, web DTOs); validate in the compact constructor and
  defensively copy collections (`List.copyOf(...)`), or SpotBugs `EI_EXPOSE_REP` fails the build.
- **`final`** on parameters (Checkstyle enforces it) and on locals; **`final var`** is the default for locals.
- **Type inference**: prefer `var` with an explicit type witness over a declared type for generic static factories:
  `final var empty = List.<String>of();`, not `final List<String> empty = List.of();`.
- **Full Javadoc** on every type, method, constructor and field, including in test sources (Checkstyle runs with
  `includeTestSourceDirectory=true`).
- **Named constants, never magic numbers**: `MagicNumber` is on and also applies to tests. Put the constant on the
  type that owns the rule.
- **Streams over loops for a simple scan**: `items.stream().anyMatch(Objects::isNull)`.
- **Modern collection accessors**: `items.getFirst()` / `items.getLast()`, never `items.get(0)` /
  `items.get(items.size() - 1)`.
- **Method references over lambdas** where the lambda only forwards its own parameter to one method
  (`names.forEach(log::info)`, not `names.forEach(name -> log.info(name))`). Keep a lambda when it does more.
- **`switch` over chained conditions** when one value is tested against several alternatives; use a `switch`
  expression when the result is a value. Chained `if`s stay for ranges or tests over different values.
- **No redundant `this`.** Drop `this.` wherever the field is not shadowed; keep it only in a constructor whose
  parameter deliberately shares the field's name (removing it there is a silent self-assignment).
- **Utility predicates over multi-branch conditions**: Spring's `StringUtils.hasText(value)` instead of
  `value == null || value.isBlank()`, `CollectionUtils.isEmpty(list)` instead of `list == null || list.isEmpty()`.
  They are on every module's classpath except `domain`, which uses its own `domain.Preconditions`
  (`requireText`, `requireTextIfPresent`, `isBlank`) so a compact constructor has no null-or-blank branches.
- **Transactions belong to the use cases.** Every `*UseCase` of `auth-server` is `@Transactional` (`readOnly = true`
  when it only reads), on the class or on each public method; its `HexagonalArchitectureTest` fails the build
  otherwise. The use cases of `resource-server` and `bff` touch no transactional store (in-memory documents, and the
  resource server behind a remote call) and carry none: a transaction there would only hold a connection across a
  remote call. Adapters never
  open a transaction of their own: a repository method with several statements runs in its caller's (the advisory
  lock's `TransactionTemplate` in `JdbcSigningKeyRepository` joins it). Only non-use-case entry points such as
  `DevDataInitializer` demarcate their own.
- **Mappers are classes.** A conversion between layers or types (domain model ↔ web DTO, ↔ framework type such as
  `UserDetails`, `RegisteredClient` or `JWK`, ↔ database row) lives in an explicit mapper of the adapter (a
  `@Component` named `*Mapper`, or a `RowMapper<T>` class), injected and unit-tested on its own; never a private
  static `toX`/`map` method inside a controller, repository or `@Configuration`. Mappers never live in `domain`.
- **Collaborators are beans.** A use case never `new`s a policy, generator or strategy: it is declared as a `@Bean`
  (for a domain type, in a `@Configuration` of `application`) and injected, so it can be replaced and mocked. Tests
  that need the real behaviour use `@Spy` with a real instance.
- **Don't reinvent infrastructure.** Rate limiting, retries, circuit breakers and caches use an established library
  (Bucket4j, Resilience4j, Caffeine), never hand-written counters, maps or loops; check for one before writing it.

### Lombok

- **Constructors**: a constructor that only assigns its parameters to `final` fields is replaced by
  `@RequiredArgsConstructor` (or `@AllArgsConstructor`/`@NoArgsConstructor`/`@Value`/`@Data` where they say the same
  thing more briefly). Keep a hand-written constructor only when it does real work: it validates with a specific
  exception type (a record rejecting a blank value with `IllegalArgumentException`), defensively copies, or derives
  something once at construction. Spring beans (use cases, adapters) take `@RequiredArgsConstructor`: Spring never
  injects `null`, so they don't null-check their dependencies.
- **Loggers**: `@Slf4j`, never a hand-rolled `LoggerFactory.getLogger(Foo.class)` field. The generated field is
  `log`.
- `@Configuration` classes with only `@Bean` methods need no constructor at all.

### Line endings are LF, and never the platform's own

Every file uses `\n`; `.gitattributes` pins `* text=auto eol=lf`. Code must never ask the platform what a newline
is: no `System.lineSeparator()`, `String.format("%n")`, `PrintWriter.println`, `BufferedWriter.newLine()` or
Jackson's `writerWithDefaultPrettyPrinter()` (pass `new DefaultIndenter("  ", "\n")`). Anything that compares
file content exactly (the API contracts and the tagged regions the docs include) must produce identical bytes on Linux, macOS and Windows.

### Locales are pinned, and never the platform's own

A response's language is a property of the request and a test's expected text is a property of the test, never of
the machine. Pass an explicit locale (`Locale.ROOT` for machine-facing text) to `toUpperCase`/`toLowerCase`,
`String.format`, `DateTimeFormatter` and `NumberFormat`. `application.yml` sets
`spring.messages.fallback-to-system-locale: false` and `spring.web.locale: en`, and a test asserting on localized text
sets `LocaleContextHolder.setLocale(Locale.ENGLISH)` first.

## Build gates

`./mvnw -B clean verify` must be green before pushing. All of these fail the build:

- **Checkstyle** (`checkstyle.xml`): `violationSeverity=warning`, test sources included.
- **PMD** and **CPD** (copy-paste detection).
- **SpotBugs**: `threshold=Medium`, `effort=Max`, exclusions only in `spotbugs-exclude.xml` with a reason each.
- **JaCoCo**: 80% line / 70% branch on the aggregated bundle in the `coverage` module (unit + integration).
- **Enforcer**: Java `[21,26)`, Maven 3.9+, and the per-module `bannedDependencies` above.
- **ArchUnit**: the hexagonal rules in each application's `boot` module.

If coverage falls short, add the missing tests; never lower the threshold. Never suppress a Checkstyle, PMD or
SpotBugs finding to make code fit unless the rule is genuinely wrong for that line, and say why next to the
suppression. `*Application` classes are excluded from coverage and carry the one `HideUtilityClassConstructor`
suppression, because a private constructor breaks Spring's configuration proxying.

CI (`.github/workflows/build.yml`) runs `verify` on every push and pull request, then the SonarCloud analysis
(organization `albertoirurueta`, project `albertoirurueta_irurueta-auth-server`) when the `SONAR_TOKEN` secret is set.
The workflow never deploys anything.

`.github/workflows/docs.yml` (*Documentation*, on every push to `main` and on demand) publishes the documentation to
the `gh-pages` branch, served at `https://albertoirurueta.github.io/irurueta-auth-server/`: the Antora site at the
root, the staged Maven site (`target/staging`: aggregated Javadoc, JaCoCo, Surefire/Failsafe, Checkstyle, PMD,
SpotBugs, JXR) under `/mvn-site/` and the API contracts and their html2 rendering under `/openapi/`. The Antora *Reference* page
links those reports, so a new report or module that should be reachable from the docs needs a row there.
