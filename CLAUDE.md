# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. Follow these
rules over any general-purpose default. Where a rule below and a generated scaffold disagree, this file wins.

## What this is

An **example** OAuth 2.1 / OpenID Connect authorization server built from scratch with Spring Boot 4.1 and Spring
Security 7.1 (Spring Authorization Server), plus the applications that use it. It backs the step-by-step guide
*Building an Authorization Server from Scratch* in the docs site (repository `albertoirurueta/docs`, under
`modules/ROOT/pages/backend/springboot/authorization-server-from-scratch/`), which includes code from this repository
with tagged regions. It is never deployed: CI only builds, analyses and tests it.

## Commands

Requires JDK 21–25 (the build enforces `[21,26)`; SpotBugs cannot parse JDK 26+ class files) and Docker for
Testcontainers.

```bash
./mvnw -B clean verify                 # unit (*Test) + integration (*IT) tests and every build gate (must be green)
./mvnw test                            # fast unit-test run only, no Spring context starts
./mvnw -pl auth-server/api/web -am test -Dtest=LoginControllerTest   # one test class in one module
./mvnw -pl auth-server/boot -am spring-boot:run -Dspring-boot.run.profiles=dev   # run one application
./mvnw verify site                     # adds the browsable Checkstyle/PMD/SpotBugs/JXR/Javadoc reports
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
| `domain` | nothing but the JDK (and Lombok, compile-only) | Spring, Jackson, JPA/JDBC, Spring Security types |
| `application` | `domain` | Spring annotations; use cases are plain classes wired as `@Bean`s in `boot` |
| `infrastructure/*` | `domain`, `application` | a sibling adapter, any `api/*` module |
| `api/*` | `domain`, `application` | any `infrastructure/*` module |
| `boot` | everything | business logic: it only wires beans, holds `application*.yml` and the integration tests |

- Package roots: `com.irurueta.authserver.authorization` (auth-server), `com.irurueta.authserver.bff`,
  `com.irurueta.authserver.resourceserver`, `com.irurueta.authserver.serviceclient`. Below each root the module
  name is the next package segment (`…authorization.domain`, `…authorization.application`,
  `…authorization.infrastructure.persistence`, `…authorization.api.web`); the `*Application` class lives in the
  root package inside `boot`, so component scanning covers every module.
- A port is an interface in `domain` (named for what it provides, for example `UserAccountRepository`); its
  implementation lives in an `infrastructure/*` adapter. A port implementation never returns `null` (an empty
  `Optional`/`List` instead) and never lets a JDBC, HTTP or framework type escape through it.
- **Domain models are never returned from a controller**; map them onto a web DTO (a record in the `api/*`
  adapter). The mapper belongs to the adapter, never to `domain`.
- Spring Security and Spring Authorization Server types (`UserDetailsService`, `RegisteredClientRepository`,
  `SecurityFilterChain`, …) are framework adapters: they live in `api/*` or `infrastructure/*`, never in `domain`
  or `application`.
- A layer is only created once it has code: an application with no driven adapter or no use case yet (for example
  `bff` until #3) has no `infrastructure` or `application` module, and `service-client` stays a single `boot` module
  until #8 gives it a domain.
- `test-support` (shared Testcontainers base), `e2e-tests` and `coverage` (JaCoCo aggregate) are root modules
  outside the applications.

### Feature layout inside `auth-server`

A feature (an authentication method or capability) spans the layers with **the same package name in each**, so it
can be developed in parallel without editing shared files: `…domain.<feature>`, `…application.<feature>`,
`…infrastructure.persistence.<feature>`, `…api.web.<feature>`. Feature names: `password`, `keys`, `tokens`,
`clients`, `login`, `mfa`, `totp`, `passkeys`, `ott`, `social`, `x509`, `implicit`, `account`, `admin`. Each
placeholder package holds a `package-info.java` saying which issue fills it.

### Extension points: adding a login method without editing shared files

- `api.web.login.LoginChainCustomizer` (a `Customizer<HttpSecurity>`): every bean of this type is applied, in
  `@Order`, to the login/UI chain by `SecurityConfig`, **before** its catch-all `anyRequest().authenticated()`, so a
  customizer may still permit its own endpoints. A new method declares one in its own `@Configuration` to enable its
  `HttpSecurity` features (for example `http.oneTimeTokenLogin(...)`); `SecurityConfig` is never edited.
- `api.web.login.LoginMethodFragment`: every bean of this type contributes a Thymeleaf fragment (`templateName()`,
  `fragmentName()`, `order()`; `reference()` builds the `template :: fragment` expression) that `LoginController`
  passes to `templates/login.html`, which renders them below the password form.

A later issue therefore adds a login method by creating its feature packages (domain model and port, use case,
persistence adapter, web `@Configuration` with its controller, a `templates/<method>.html`, a `LoginChainCustomizer`
bean and a `LoginMethodFragment` bean), plus its own Flyway migration in its range. No existing file needs to change.

### Flyway ranges

Migrations live in `auth-server/infrastructure/persistence/src/main/resources/db/migration`
(`classpath:db/migration`). The skeleton (#1) uses `V100`–`V199` (`V100` Spring Authorization Server schema, `V101`
users). Each issue states its own range in its body; never write a migration outside it.

## Conventions

- Every source file starts with the Apache 2.0 header used in the existing files.
- Never commit secrets, keys or certificates: generate dev keys at first start and test keys inside the tests.
- Code shown in the docs guide is wrapped in tag comments, see below. Never rename or remove a tag without updating
  the docs repository.
- Every new endpoint carries springdoc-openapi annotations, and the committed OpenAPI documents under `openapi/` are
  regenerated by a drift test (see Testing).

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

- `test-support` holds `PostgresTestConfiguration` (a `postgres:18` Testcontainers container exposed through
  `@ServiceConnection`) and the `@PostgresIT` meta-annotation: `@SpringBootTest` wired to that container, with a
  `webEnvironment()` attribute for `RANDOM_PORT` tests. Consumers depend on it with `<scope>test</scope>`.
- `e2e-tests` drives the packaged `auth-server` and `bff` boot jars through headless Chromium with Playwright for
  Java (chosen over Selenium because it manages its own browser binaries, auto-waits for elements and needs no
  driver setup). It must stay last in the reactor, before `coverage`.
- `openapi/auth-server.json` is the committed OpenAPI contract; `OpenApiDriftIT` fails when `/v3/api-docs` differs.
  Regenerate with `./mvnw -pl auth-server/boot -am verify -Dopenapi.update=true` and commit the result. springdoc
  only documents the `api` group (`/api/**`, see `OpenApiConfig`): put every new REST endpoint of `auth-server` under
  `/api/**`, or widen the group, otherwise the drift test does not cover it. The comparison writes and reads with
  `\n` line endings (see below).
- The `dev` profile of `auth-server` resolves `../../compose.yaml` against the working directory (`spring-boot:run`
  uses the `boot` module directory); elsewhere, set `SPRING_DOCKER_COMPOSE_FILE` to the root `compose.yaml`.

## Java style

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
  They are on every module's classpath except `domain`, which uses plain JDK checks.

### Lombok

- **Constructors**: a constructor that only assigns its parameters to `final` fields is replaced by
  `@RequiredArgsConstructor` (or `@AllArgsConstructor`/`@NoArgsConstructor`/`@Value`/`@Data` where they say the same
  thing more briefly). Keep a hand-written constructor only when it does real work: it validates with a specific
  exception type (a use case rejecting a null port with `IllegalArgumentException`), defensively copies, or derives
  something once at construction.
- **Loggers**: `@Slf4j`, never a hand-rolled `LoggerFactory.getLogger(Foo.class)` field. The generated field is
  `log`.
- `@Configuration` classes with only `@Bean` methods need no constructor at all.

### Line endings are LF, and never the platform's own

Every file uses `\n`; `.gitattributes` pins `* text=auto eol=lf`. Code must never ask the platform what a newline
is: no `System.lineSeparator()`, `String.format("%n")`, `PrintWriter.println`, `BufferedWriter.newLine()` or
Jackson's `writerWithDefaultPrettyPrinter()` (pass `new DefaultIndenter("  ", "\n")`). Anything that compares
file content exactly (the OpenAPI drift test) must produce identical bytes on Linux, macOS and Windows.

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
