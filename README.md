# JSON Schema Contract Gate — `dev.mcpg.tool-gate.schema`

> class `tool_gate` · `native` · package `mcpg-plugin-tool-gate-schema` · artifact `libmcpg_plugin_tool_gate_schema.so` · Apache-2.0

A pre-dispatch tool gate that validates MCP tool-call **arguments** against an
operator-supplied inline JSON Schema and rejects malformed calls with a precise
4xx — JSON-RPC `-32602` *Invalid params* over HTTP 400 by default — before the
call ever reaches a backend. The schema is compiled once when the plugin loads,
so per-call validation is pure CPU with no allocation of a fresh validator and
no network access at all. Reach for it when a tool's contract is stricter than
its advertised `input_schema` and you want the violation refused at the security
gate, with a status code you choose, rather than surfaced as a backend error.

## What it does
- Validates the tool-call arguments against an inline JSON Schema on every
  pre-dispatch evaluation; a conforming call is allowed unchanged.
- Compiles the schema once at load. A schema that does not compile, or a config
  object with an unknown key, refuses to instantiate — the gateway fails to boot
  rather than running with an unenforced contract.
- Resolves in-document `$ref` (`#/$defs/Foo`) locally and never fetches a remote
  `$ref`; the validator is built without HTTP resolution, so the gate has no
  outbound dependency and declares no required capabilities.
- Scopes validation to a sub-value of the arguments through an optional RFC 6901
  JSON Pointer; a pointer that does not resolve is itself a denial.
- Reports up to `max_errors` failing instance paths in the deny message and
  appends a truncation marker beyond that, so a pathological payload cannot
  inflate the error response.
- Suppresses all schema detail when `deny_message` is set, for contracts whose
  shape is itself sensitive.
- Allows unconditionally post-dispatch — this is a contract gate on the way in,
  not a result inspector.

## Configuration
Loaded from the flat top-level `plugins:` list. Gates evaluate in `plugins:`
array order, so place this entry ahead of anything that should only see
well-formed arguments.

```yaml
plugins:
  - id: dev.mcpg.tool-gate.schema
    class: tool_gate
    source:
      oci: ghcr.io/mcpg-dev/source-code/plugins/tool-gate-schema:protocol-1
    config:
      schema:
        type: object
        required: ["query"]
        properties:
          query: { type: string, minLength: 1 }
          limit: { type: integer, maximum: 100 }
      max_errors: 8
```

| Field | Type | Default | Description |
|---|---|---|---|
| `schema` | object (JSON Schema) | *(required)* | The schema arguments must satisfy. In-document `$ref` only. |
| `pointer` | string (JSON Pointer) | *(whole arguments object)* | Validate only the arguments sub-value at this RFC 6901 pointer. |
| `max_errors` | integer | `32` | Cap on validation errors listed in the deny message. |
| `code` | integer | `-32602` | JSON-RPC error code carried by the deny. |
| `http_status` | integer | `400` | HTTP status carried by the deny. |
| `deny_message` | string | *(detailed message)* | Fixed deny text. When set, no schema error detail reaches the caller. |

Unknown fields are rejected.

Against the example above, arguments of `{"limit": 250}` are denied with HTTP
400 / `-32602` and a message naming both the missing `query` and the
out-of-range `/limit`.

## Security
The plugin is a fail-closed control on both edges. Bad operator input — invalid
config JSON, an unknown config key, or a schema the validator rejects — aborts
instantiation instead of degrading to allow-everything, so a typo in the
contract cannot silently disable it. On the request edge, anything the schema
does not accept is denied, including a `pointer` whose target is absent.

The default deny message echoes the failing instance paths, which is useful for
callers you trust and an information leak for callers you do not. Set
`deny_message` to a fixed string when the schema encodes internal field names,
regulated identifiers, or any other detail the caller should not learn.

## Build
Default feature set is OFF (avoids `mcpg_plugin_register` linker
collisions in the workspace build); opt in to the cdylib:

```bash
cargo build -p mcpg-plugin-tool-gate-schema --features cdylib-export --release   # → target/release/libmcpg_plugin_tool_gate_schema.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes and the plugin ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema: <https://mcpg.dev/docs/reference/configuration>
- `mcpg-plugin-transform-json-schema` — the same validator as a transform: an
  invalid value becomes a transform error in the pipeline instead of a gate
  denial with a chosen status code.
