# Burp Suite MCP Server Extension

## Overview

Integrate Burp Suite with AI Clients using the Model Context Protocol (MCP).

For more information about the protocol visit: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

## About this fork

This fork extends the upstream [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) extension with the ability to **drive Burp's Scanner and target Scope from MCP**, plus introspection tools so an MCP client can describe what an audit will do before launching it. Everything below is additive — all upstream tools and behaviour are preserved.

### New MCP tools (11)

#### Scanner control (Burp Professional only)

Registered inside the existing `if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL)` block in `Tools.kt::registerTools`. Each Pro tool is absent from the `tools/list` reply on Community editions.

| Tool | Purpose |
|---|---|
| `start_crawl` | Start a Burp crawl with a list of seed URLs. Validates each URL has an `http` or `https` scheme and a non-blank host. Deduplicates approval prompts per unique `(host, port)` (case-insensitive on host). Aborts on first denial without registering the task. Returns a `task_id`. |
| `start_audit` | Start a Burp audit with a seed HTTP request. `mode` is `ACTIVE` (probe payloads sent) or `PASSIVE` (passive checks against the seed only — no probes). The audit is registered in the in-process registry **before** the seed `addRequest` call, so a failure during seeding can be cleaned up cleanly. Returns a `task_id`. |
| `add_request_to_audit` | Extend a running audit with another HTTP request without restarting it. Wraps Montoya's `Audit.addRequest`. The only mid-flight scan-extension capability the Montoya 2025.10 API exposes. |
| `get_scan_task_status` | Returns progress info for a crawl or audit: `requestCount`, `errorCount`, `statusMessage` (audits only — Montoya's `Crawl.statusMessage()` is documented as not implemented), `insertionPointCount` (audits), `issuesFound` (audits). Each Burp accessor is wrapped in `runCatching{}.getOrNull()` so a single accessor throwing `"Currently unsupported."` (which Burp does on some accessors mid-flight, and on `audit.issues()` even after completion) still returns partial status instead of failing the whole tool call. |
| `list_scan_tasks` | Paginated list of all in-process tracked scan tasks (`task_id`, `kind`, `requestCount`, `errorCount`). |
| `cancel_scan_task` | Cancels a task via `ScanTask.delete()` and removes it from the registry. If `delete()` throws, the task is left in the registry so the caller can retry, and the actual error is surfaced to the response (early implementations silently lied about success). |

#### Introspection (Burp Professional only)

| Tool | Purpose |
|---|---|
| `describe_audit_modes` | Pure-documentation tool, no Burp API call. Returns a structured JSON describing what each `start_audit` mode actually does, the underlying `BuiltInAuditConfiguration` enum value, what is **not** configurable from the Montoya API (per-check filtering, named scan configs, severity pre-filtering), the actual severity enum values (`HIGH/MEDIUM/LOW/INFORMATION/FALSE_POSITIVE` — there is no `CRITICAL`), and a `seeAlso` cross-reference. |
| `get_scanner_configuration` | Reads Burp's `exportProjectOptionsAsJson()`, slices out the scanner-relevant top-level keys, and returns them as JSON capped at 5000 chars. If the expected scanner subtree is absent, falls back to returning the full JSON with an explanatory note. |

#### Suite-wide scope (any Burp edition)

| Tool | Purpose |
|---|---|
| `is_in_scope` | Wraps `api.scope().isInScope(url)`. Returns `"true"` or `"false"`. |
| `include_in_scope` | Wraps `api.scope().includeInScope(url)`. **Gated by the existing `Enable tools that can edit your config` setting** in the MCP tab — no new toggle introduced. Returns the standard tooling-disabled message when off. |
| `exclude_from_scope` | Wraps `api.scope().excludeFromScope(url)`. Same gate as `include_in_scope`. |

### Enhanced existing tool

**`get_scanner_issues`** gained two optional parameters and per-item truncation:

- `host: String?` — case-insensitive hostname filter. `siteMap().issues()` is project-cumulative across every audit ever run, which can return tens of MB on a real project; this filter restricts results to a single target.
- `minSeverity: String?` — one of `HIGH`, `MEDIUM`, `LOW`, `INFORMATION`, `FALSE_POSITIVE`. Returns only issues at or above the threshold. Case-insensitive. Invalid values produce a clear error listing the valid options.
- Each returned item is now truncated to 5000 chars to bound the per-item size, matching the existing `get_proxy_http_history*` tools.

Both filters compose. The original no-filter behaviour is preserved by omitting them.

### Internal additions

- **`tools/ScanTaskRegistry.kt`** (new file) — singleton in-process registry holding scan tasks by UUID. Implemented as a sealed class so `add_request_to_audit` and `get_scan_task_status` pattern-match (`when (val r = registry.get(id)) { is RegisteredScanTask.Crawl -> ...; is RegisteredScanTask.Audit -> ... }`) instead of using unsafe `as` casts. Backed by `ConcurrentHashMap` for parallel SSE worker threads. Concurrency-tested with 200 parallel coroutine registrations.
- **`schema/serialization.kt`** — added `ScanTaskStatus` and `ScanTaskSummary` for the status/list response shapes.
- **`ExtensionBase.kt`** — the existing `registerUnloadingHandler` now calls `ScanTaskRegistry.list().forEach { runCatching { it.task.delete() } }` followed by `ScanTaskRegistry.clear()` *before* shutting down the SSE server, so disabling or unloading the extension cancels any in-flight Burp scans rather than orphaning them.

### Bug fixes & safety improvements found during development

| | Issue | Fix |
|---|---|---|
| 1 | `start_crawl` accepted `file://`, `gopher://` etc. and asked the user to approve `:80` with an empty host | Validate scheme is `http` or `https` and host is non-blank before the approval check. |
| 2 | `start_audit` could leak the audit to Burp if `addRequest` threw, with no `task_id` returned to cancel it | Register the audit immediately, then attempt `addRequest` in `try/catch` that calls `audit.delete()` and removes the registry entry on failure. |
| 3 | `cancel_scan_task` reported `"Cancelled"` even when `Burp.delete()` threw | `runCatching{}.fold(...)` — keep the registry entry on failure, surface the underlying exception to the caller. |
| 4 | `start_crawl` dedupe key was case-sensitive on host (`Example.com` vs `example.com` → two prompts for what Burp considers one host) | Lowercase the host before keying the dedupe map. |
| 5 | `get_scan_task_status` crashed mid-audit because Burp throws `"Currently unsupported."` on some accessors before completion | Wrap each accessor in `runCatching{}.getOrNull()`; nullable fields are simply omitted from the JSON when unavailable. |
| 6 | `get_scanner_issues` could return tens of MB on a real project | Per-item 5000-char truncation, plus the `host` and `minSeverity` filters above. |
| 7 | Test fixture had a dead `getString("autoApproveTargets")` stub — the actual `McpConfig` property is `_autoApproveTargets` (with leading underscore), so any test exercising the auto-approve list would have failed | Corrected the stub key. |
| 8 | The `persistedObject` test mock was init-block-local, preventing tests from re-stubbing individual keys (e.g. flipping `requireHttpRequestApproval` to test denial paths) | Promoted to a class field. |

### Test coverage

JUnit 5 + MockK + Kotlin coroutines, integration-style (real `KtorServerManager` + `TestSseMcpClient.callTool` over SSE).

- `ScanTaskRegistryTest` (new) — register/get/remove/list/clear plus a 200-coroutine concurrency test.
- `ToolsKtTest`'s existing `ScannerToolsTests` and `ScopeToolsTests` (new nested classes) cover happy paths, denial paths (with the `HttpRequestSecurity.approvalHandler` swapped at test time), case-insensitive dedupe, defensive accessor wrapping, host/severity filters, and the `configEditingTooling` gate for scope writes.
- The existing edition-gating test (`edition specific tools should only register in professional edition`) was extended to assert all six new scanner tools and both introspection tools are absent on Community and present on Professional, while the three scope tools are available on both.
- Build: `./gradlew test` — 101 tests, all green. `./gradlew embedProxyJar` produces `build/libs/burp-mcp-all.jar` as before.

## Features

- Connect Burp Suite to AI clients through MCP
- Automatic installation for Claude Desktop
- Comes with packaged Stdio MCP proxy server

## Usage

- Install the extension in Burp Suite
- Configure your Burp MCP server in the extension settings
- Configure your MCP client to use the Burp SSE MCP server or stdio proxy
- Interact with Burp through your client!

## Installation

### Prerequisites

Ensure that the following prerequisites are met before building and installing the extension:

1. **Java**: Java must be installed and available in your system's PATH. You can verify this by running `java --version` in your terminal.
2. **jar Command**: The `jar` command must be executable and available in your system's PATH. You can verify this by running `jar --version` in your terminal. This is required for building and installing the extension.

### Building the Extension

1. **Clone the Repository**: Obtain the source code for the MCP Server Extension.
   ```
   git clone https://github.com/PortSwigger/mcp-server.git
   ```

2. **Navigate to the Project Directory**: Move into the project's root directory.
   ```
   cd mcp-server
   ```

3. **Build the JAR File**: Use Gradle to build the extension.
   ```
   ./gradlew embedProxyJar
   ```

   This command compiles the source code and packages it into a JAR file located in `build/libs/burp-mcp-all.jar`.

### Loading the Extension into Burp Suite

1. **Open Burp Suite**: Launch your Burp Suite application.
2. **Access the Extensions Tab**: Navigate to the `Extensions` tab.
3. **Add the Extension**:
    - Click on `Add`.
    - Set `Extension Type` to `Java`.
    - Click `Select file ...` and choose the JAR file built in the previous step.
    - Click `Next` to load the extension.

Upon successful loading, the MCP Server Extension will be active within Burp Suite.

## Configuration

### Configuring the Extension
Configuration for the extension is done through the Burp Suite UI in the `MCP` tab.
- **Toggle the MCP Server**: The `Enabled` checkbox controls whether the MCP server is active.
- **Enable config editing**: The `Enable tools that can edit your config` checkbox allows the MCP server to expose tools which can edit Burp configuration files.
- **Advanced options**: You can configure the port and host for the MCP server. By default, it listens on `http://127.0.0.1:9876`.

### Claude Desktop Client

To fully utilize the MCP Server Extension with Claude, you need to configure your Claude client settings appropriately.
The extension has an installer which will automatically configure the client settings for you.

1. Currently, Claude Desktop only support STDIO MCP Servers
   for the service it needs.
   This approach isn't ideal for desktop apps like Burp, so instead, Claude will start a proxy server that points to the
   Burp instance,  
   which hosts a web server at a known port (`localhost:9876`).

2. **Configure Claude to use the Burp MCP server**  
   You can do this in one of two ways:

    - **Option 1: Run the installer from the extension**
      This will add the Burp MCP server to the Claude Desktop config.

    - **Option 2: Manually edit the config file**  
      Open the file located at `~/Library/Application Support/Claude/claude_desktop_config.json`,
      and replace or update it with the following:
      ```json
      {
        "mcpServers": {
          "burp": {
            "command": "<path to Java executable packaged with Burp>",
            "args": [
                "-jar",
                "/path/to/mcp/proxy/jar/mcp-proxy-all.jar",
                "--sse-url",
                "<your Burp MCP server URL configured in the extension>"
            ]
          }
        }
      }
      ```

3. **Restart Claude Desktop** - assuming Burp is running with the extension loaded.

## Manual installations
If you want to install the MCP server manually you can either use the extension's SSE server directly or the packaged
Stdio proxy server.

### SSE MCP Server
In order to use the SSE server directly you can just provide the url for the server in your client's configuration. Depending
on your client and your configuration in the extension this may be with or without the `/sse` path.
```
http://127.0.0.1:9876
```
or
```
http://127.0.0.1:9876/sse
```

### Stdio MCP Proxy Server
The source code for the proxy server can be found here: [MCP Proxy Server](https://github.com/PortSwigger/mcp-proxy)

In order to support MCP Clients which only support Stdio MCP Servers, the extension comes packaged with a proxy server for
passing requests to the SSE MCP server extension.

If you want to use the Stdio proxy server you can use the extension's installer option to extract the proxy server jar.
Once you have the jar you can add the following command and args to your client configuration:
```
/path/to/packaged/burp/java -jar /path/to/proxy/jar/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```

### Creating / modifying tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`. To define new tools, create a new serializable
data class with the required parameters which will come from the LLM.

The tool name is auto-derived from its parameters data class. A description is also needed for the LLM. You can return
a string (or richer PromptMessageContents) to provide data back to the LLM.

Extend the Paginated interface to add auto-pagination support.
