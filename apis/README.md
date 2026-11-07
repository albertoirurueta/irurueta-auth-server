# API contracts

Every HTTP endpoint the applications handle themselves, JSON or HTML page, is defined here, **contract first**: the
OpenAPI document is the source of truth, openapi-generator turns it into Spring interfaces (and DTOs) at build time,
and the hand-written controllers only implement those interfaces by calling use cases. No hand-written class carries a
mapping annotation (`@RequestMapping`, `@GetMapping`, ...): `HexagonalArchitectureTest` fails the build otherwise.
`apis/` is not a Maven module; it is where a reviewer looks to see everything the applications expose.

## Layout

The repository holds several applications, so the contracts are grouped by application first, then by kind of
contract (the single-service layout `apis/rest-server/` gains one level):

```
apis/
  README.md
  auth-server/
    rest-server/
      auth-server-api-v1.yaml       account, client and signing-key administration (/api/**)
    web-pages/
      auth-server-pages-v1.yaml     server-rendered HTML pages (/login, /oauth2/consent, /logout, /account/passkeys, /account/phone, /login/ott, /login/ott/confirm, /oauth2/device_verification, /dev/sms-inbox)
  resource-server/
    rest-server/
      resource-server-api-v1.yaml   documents API (/api/**)
  bff/
    rest-server/
      bff-api-v1.yaml               JSON endpoints of the BFF (/bff/**) and its documents API (/api/documents)
```

| Contract | Generated into | Packages | Implemented by |
|---|---|---|---|
| `auth-server/rest-server/auth-server-api-v1.yaml` | `auth-server/api/web` | `com.irurueta.authserver.authorization.api.web.v1.generated.{api,model}` | `AccountController`, `ClientAdminController`, `SigningKeyAdminController`, `PasskeyController`, `PhoneController`, `IdentityController` |
| `resource-server/rest-server/resource-server-api-v1.yaml` | `resource-server/api/web` | `com.irurueta.authserver.resourceserver.api.web.v1.generated.{api,model}` | `DocumentController` |
| `auth-server/web-pages/auth-server-pages-v1.yaml` | `auth-server/api/web` | `com.irurueta.authserver.authorization.api.web.pages.v1.generated.{api,model}` | `LoginController`, `ConsentController`, `LogoutController`, `PasskeysPageController`, `PhonePageController`, `OttPagesController`, `DeviceVerificationController`, `DevSmsInboxController` (dev profile only) |
| `bff/rest-server/bff-api-v1.yaml` | `bff/api/web` | `com.irurueta.authserver.bff.api.web.v1.generated.{api,model}` | `UserController`, `BffLoginController`, `DocumentsController` |

### HTML pages

The server-rendered pages are operations like any other: each answers `200` (and any error status it can answer) as
`text/html` with a `string` schema, and the generated method returns `ResponseEntity<String>`. The controller builds
the model and hands the Thymeleaf template to `PageRenderer` (`auth-server/api/web`, package `…api.web.pages`), which
resolves the view through the application's view resolvers with the request's locale and renders it against the
current request into a capturing response wrapper, so the CSRF hidden fields, `@{...}` links and messages keep
working, and adds the branding. The pages contract has its own springdoc group, `pages`, served at
`/v3/api-docs/pages`.

A page that exists only in the `dev` profile (`/dev/sms-inbox`, the SMS the logging sender recorded) is in the pages
contract like any other, marked in its description; `OpenApiDriftIT` runs without that profile and leaves the `/dev/`
paths out of the comparison.

### Clients of another service

A service that calls another one does it through a client generated from the provider's own contract, never through a
hand-written pass-through: the BFF's `bff/infrastructure/resourceserver` module generates a `java` / `restclient`
client from `resource-server/rest-server/resource-server-api-v1.yaml` into
`com.irurueta.authserver.bff.infrastructure.resourceserver.v1.generated.{api,model}` (plus the `ApiClient` in
`…v1.generated`). The client stays inside that driven adapter, behind the domain port `DocumentGateway`
(`RestDocumentGateway`); the BFF exposes the operations its browser front end needs in its own contract
(`/api/documents`), and its controller calls use cases, never the client. The execution in that module's pom replaces
the shared server options with the client's own (`combine.self="override"`) and only generates the supporting files
the client needs (`ApiClient`, the authentication classes and their helpers).

### What is not in a contract

Only endpoints owned by frameworks: the OAuth 2.1 / OpenID Connect protocol endpoints of the authorization server
(`/oauth2/**`, `/.well-known/**`, `/connect/**`, `/userinfo`, ...), which are defined by their specifications, the
Spring Security filters (`POST /login`, `POST /logout`, the BFF's `POST /bff/logout`, `/oauth2/authorization/**` and
`/login/oauth2/**`, and the one-time token endpoints `POST /ott/generate`, `POST /login/ott` and `POST /login/second-factor/ott`), Spring Boot's error controller (`/error`, rendered through `ErrorPageViewResolver` in the
authorization server) and actuator.

## Code generation

`openapi-generator-maven-plugin` runs in the `generate-sources` phase of each `api/web` module:

- `spring` generator, `interfaceOnly` and `skipDefaultInterface`: one interface per tag (`AccountApi`, `ClientsApi`,
  `SigningKeysApi`, `DocumentsApi`, `UserApi`, `LoginApi`, `LoginPageApi`, `ConsentPageApi`, `LogoutPageApi`) with
  abstract methods only, so a controller that misses an operation
  does not compile; Java records for the DTOs (`useRecords`); Spring Boot 4, Jakarta EE and Jackson 3
  (`useSpringBoot4`, `useJackson3`).
- Bean Validation from the contract's constraints (`useBeanValidation`): `required` becomes `@NotNull`, `minLength`
  `@Size`, `pattern` `@Pattern`, `format: email` `@Email`. A non-blank string is written `minLength: 1` plus
  `pattern: '[\s\S]*\S[\s\S]*'`, the portable equivalent of `@NotBlank`.
- `format: duration` and `format: date-time` map to `java.time.Duration` and `java.time.Instant`, the types the
  domain uses, so the JSON on the wire stays ISO-8601.
- `format: password` marks a secret: the generated record leaves it out of `toString()`, so it never reaches a log.
- The generated interfaces carry springdoc annotations (`documentationProvider=springdoc`), so each application keeps
  serving its OpenAPI document at `/v3/api-docs` (and the Swagger UI where it ships one) with the contract's
  descriptions.
- A second execution renders the contract as a standalone HTML page (`html2` generator) into
  `<module>/target/generated-docs/rest-server/v1/index.html` (and, for the pages contract,
  `auth-server/api/web/target/generated-docs/web-pages/v1/index.html`); the Documentation workflow publishes them.

The shared generator options live in the root `pom.xml` (`pluginManagement`); each `api/web` pom only names its
contracts and packages. A client module (see above) overrides them with the `java` generator's own.

Generated code lands in `<module>/target/generated-sources/openapi`. It is **never committed and never edited**: if
something about it is wrong, fix the contract or the generator configuration. It is left out of Checkstyle (which
only reads `src/main/java`), PMD/CPD (`excludeRoots`), SpotBugs (`spotbugs-exclude.xml`), JaCoCo (`**/generated/**`)
and Sonar (`sonar.exclusions`).

Regenerate with:

```bash
./mvnw generate-sources                                  # every contract
./mvnw -pl auth-server/api/web -am generate-sources      # one application
```

## Writing a contract

- OpenAPI 3.1. Every operation has an `operationId`, a `summary`, a `description` and every status code it can
  answer; every schema and every property has a `description`, and every constraint is expressed in the contract,
  since the constraints become the validation and the descriptions become the documentation.
- Errors are RFC 9457 problem details, `application/problem+json`, described by the `Problem` schema. Bearer-token
  failures (RFC 6750) are answered by the security filter chain with a `WWW-Authenticate` challenge and no body.
- The scope an operation needs is listed as the role of its security requirement (`bearer: [ admin ]`), which OpenAPI
  3.1 allows for non-OAuth schemes.
- A mapper per feature (`ClientDtoMapper`, `SigningKeyDtoMapper`, `DocumentDtoMapper`, `SessionUserDtoMapper`) in the
  `api/web` module converts between the generated DTOs and the domain; a controller never returns a domain model. A
  client adapter has its own mapper from the generated client model to the domain (`DocumentMapper`).
- An HTML page declares its answers as `text/html` with a `string` schema, and its security as the session cookie of
  the application (`session`, an `apiKey` in a cookie), like the BFF's JSON endpoints.

## Versioning

A contract is versioned in its **file name** (`-v1.yaml`) and in the **package** its code generates into (`.v1.`),
never by editing it in place incompatibly. A breaking change means a `-v2.yaml` next to the `-v1.yaml`, with its own
generator execution and `.v2.` packages; both keep generating and both are served until `v1` is retired.

The single-service convention also puts the version in the paths (`/v1/...`). These contracts do not: they describe
the paths the applications already served before the contracts existed (`/api/...`, `/bff/...`), and changing them
would break every client. A `v2` contract would introduce versioned paths.

## Drift protection

`OpenApiDriftIT`, in each application's `boot` module, starts the application, fetches the OpenAPI document springdoc
serves (`/v3/api-docs`, and `/v3/api-docs/pages` for the pages of the authorization server) and compares it with the
contract through `OpenApiContract` (in `test-support`): operations, operation ids,
tags, security requirements, parameters, request bodies, status codes with their media types and schemas, and the
properties of every schema. Descriptions are not compared: they come from the contract through the generated
annotations. The test fails when an endpoint is mapped by hand outside the generated interfaces, or when a
controller stops implementing an operation. Nothing is written, so it does not depend on the platform's line endings.
