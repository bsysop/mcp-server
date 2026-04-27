package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.ScanTaskStatus
import net.portswigger.mcp.schema.ScanTaskSummary
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HistoryAccessSecurity
import net.portswigger.mcp.security.HistoryAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import java.awt.KeyboardFocusManager
import java.net.URI
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkHistoryPermissionOrDeny(
    accessType: HistoryAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = HistoryAccessSecurity.checkHistoryAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = content.replace("\r", "").replace("\n", "\r\n")

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

        val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
            orderedPseudoHeaderNames.forEach { name ->
                val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
                if (value != null) {
                    put(name, value)
                }
            }

            pseudoHeaders.forEach { (key, value) ->
                val properKey = if (key.startsWith(":")) key else ":$key"
                if (!containsKey(properKey)) {
                    put(properKey, value)
                }
            }
        }

        val headerList = (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates a new Repeater tab with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportProjectOptionsAsJson()
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportUserOptionsAsJson()
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>(
            "Displays information about issues identified by the scanner. Burp's site map keeps issues " +
            "from every previous scan in the project — without filters this can be very large.\n\n" +
            "Optional filters:\n" +
            "- 'host' (case-insensitive): restrict to a single target hostname.\n" +
            "- 'minSeverity': one of HIGH, MEDIUM, LOW, INFORMATION, FALSE_POSITIVE — returns only " +
            "issues at that severity or higher (HIGH > MEDIUM > LOW > INFORMATION > FALSE_POSITIVE). " +
            "E.g. minSeverity='MEDIUM' returns HIGH and MEDIUM issues.\n\n" +
            "Each item is truncated to 5000 chars."
        ) {
            val severityRank = listOf("HIGH", "MEDIUM", "LOW", "INFORMATION", "FALSE_POSITIVE")
            val minRank = if (minSeverity.isNullOrBlank()) {
                severityRank.size - 1
            } else {
                val idx = severityRank.indexOf(minSeverity.uppercase())
                if (idx < 0) {
                    return@mcpPaginatedTool sequenceOf(
                        "Invalid minSeverity '$minSeverity'. Must be one of: ${severityRank.joinToString(", ")}"
                    )
                }
                idx
            }
            val hostFilter = host
            val all = api.siteMap().issues().asSequence()
            val byHost = if (hostFilter.isNullOrBlank()) all else all.filter {
                it.httpService()?.host()?.equals(hostFilter, ignoreCase = true) == true
            }
            val bySeverity = byHost.filter { issue ->
                val rank = severityRank.indexOf(issue.severity().name)
                rank in 0..minRank
            }
            bySeverity.map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }

        mcpTool<StartCrawl>(
            "Starts a Burp Scanner crawl with the given seed URLs. Returns a task_id that can be passed " +
            "to get_scan_task_status, list_scan_tasks, or cancel_scan_task. Crawl coverage is fixed at " +
            "start — Burp does not support adding more seed URLs to a running crawl. Seed URLs must use " +
            "http or https and have a host. The user is prompted once per unique target host:port; if " +
            "any target is denied the entire crawl is aborted."
        ) {
            if (seedUrls.isEmpty()) {
                return@mcpTool "At least one seed URL is required"
            }

            data class CrawlTarget(val host: String, val port: Int, val https: Boolean)
            val targetToSeeds = LinkedHashMap<CrawlTarget, MutableList<String>>()

            for (urlString in seedUrls) {
                val parsed = try {
                    URI(urlString).toURL()
                } catch (e: Exception) {
                    return@mcpTool "Invalid seed URL '$urlString': ${e.message}"
                }
                val protocol = parsed.protocol?.lowercase()
                if (protocol != "http" && protocol != "https") {
                    return@mcpTool "Seed URL must use http or https: $urlString"
                }
                val host = parsed.host?.lowercase()
                if (host.isNullOrBlank()) {
                    return@mcpTool "Seed URL must have a host: $urlString"
                }
                val https = protocol == "https"
                val port = if (parsed.port == -1) (if (https) 443 else 80) else parsed.port
                targetToSeeds.getOrPut(CrawlTarget(host, port, https)) { mutableListOf() }.add(urlString)
            }

            for ((target, seedsForTarget) in targetToSeeds) {
                val allowed = runBlocking {
                    HttpRequestSecurity.checkHttpRequestPermission(
                        target.host, target.port, config,
                        "Crawl seed URLs for ${target.host}:${target.port}:\n" + seedsForTarget.joinToString("\n"),
                        api
                    )
                }
                if (!allowed) {
                    api.logging().logToOutput("MCP start_crawl denied for ${target.host}:${target.port}")
                    return@mcpTool "Crawl denied by Burp Suite for ${target.host}:${target.port}"
                }
            }

            api.logging().logToOutput("MCP start_crawl with ${seedUrls.size} seed URL(s) across ${targetToSeeds.size} target(s)")
            val crawl = api.scanner().startCrawl(
                CrawlConfiguration.crawlConfiguration(*seedUrls.toTypedArray())
            )
            val taskId = ScanTaskRegistry.register(crawl)

            val response = buildJsonObject {
                put("task_id", JsonPrimitive(taskId))
                put("kind", JsonPrimitive("CRAWL"))
                put("seed_urls", buildJsonArray { seedUrls.forEach { add(JsonPrimitive(it)) } })
            }
            response.toString()
        }

        mcpTool<StartAudit>(
            "Starts a Burp Scanner audit on the given seed HTTP request. Mode is 'ACTIVE' (Burp sends " +
            "probe payloads to detect vulnerabilities) or 'PASSIVE' (Burp runs only passive checks " +
            "against the seed request — no probes are sent). Returns a task_id. Use " +
            "add_request_to_audit to extend the audit with additional requests without restarting it. " +
            "Call describe_audit_modes for what each mode actually does, and get_scanner_configuration " +
            "to see the project's current Burp scanner settings before deciding."
        ) {
            val builtIn = when (mode.uppercase()) {
                "ACTIVE" -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
                "PASSIVE" -> BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                else -> return@mcpTool "Invalid mode '$mode'. Must be ACTIVE or PASSIVE."
            }

            val allowed = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(
                    seedRequest.targetHostname, seedRequest.targetPort, config, seedRequest.content, api
                )
            }
            if (!allowed) {
                api.logging().logToOutput("MCP start_audit denied for ${seedRequest.targetHostname}:${seedRequest.targetPort}")
                return@mcpTool "Audit denied by Burp Suite"
            }

            api.logging().logToOutput("MCP start_audit ($mode) on ${seedRequest.targetHostname}:${seedRequest.targetPort}")

            val fixedContent = seedRequest.content.replace("\r", "").replace("\n", "\r\n")
            val request = HttpRequest.httpRequest(seedRequest.toMontoyaService(), fixedContent)
            val audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(builtIn))
            val taskId = ScanTaskRegistry.register(audit)

            try {
                audit.addRequest(request)
            } catch (e: Exception) {
                runCatching { audit.delete() }.onFailure {
                    api.logging().logToError("Failed to delete leaked audit ${taskId}: ${it.message}")
                }
                ScanTaskRegistry.remove(taskId)
                api.logging().logToError("Failed to seed audit ${taskId}: ${e.message}")
                return@mcpTool "Failed to seed audit: ${e.message}"
            }

            val response = buildJsonObject {
                put("task_id", JsonPrimitive(taskId))
                put("kind", JsonPrimitive("AUDIT"))
                put("mode", JsonPrimitive(mode.uppercase()))
            }
            response.toString()
        }

        mcpTool<AddRequestToAudit>(
            "Adds an additional HTTP request to a running audit task without restarting it. For an " +
            "ACTIVE audit, Burp will run the active checks against the new request (sending probe " +
            "requests). For a PASSIVE audit, Burp will only run passive checks against the new " +
            "request — it will not send probe requests, but it does still analyse the supplied request."
        ) {
            val auditEntry = when (val registered = ScanTaskRegistry.get(taskId)) {
                null -> return@mcpTool "Unknown task_id: $taskId"
                is RegisteredScanTask.Crawl -> return@mcpTool "Task $taskId is a CRAWL task, not an AUDIT — cannot add requests"
                is RegisteredScanTask.Audit -> registered
            }

            val allowed = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(
                    request.targetHostname, request.targetPort, config, request.content, api
                )
            }
            if (!allowed) {
                api.logging().logToOutput("MCP add_request_to_audit denied for ${request.targetHostname}:${request.targetPort}")
                return@mcpTool "Add request denied by Burp Suite"
            }

            api.logging().logToOutput("MCP add_request_to_audit on task $taskId")
            val fixedContent = request.content.replace("\r", "").replace("\n", "\r\n")
            val httpRequest = HttpRequest.httpRequest(request.toMontoyaService(), fixedContent)
            auditEntry.task.addRequest(httpRequest)

            "Added request to audit task $taskId"
        }

        mcpTool<GetScanTaskStatus>(
            "Returns progress information for a running or completed scan task: kind, request count, " +
            "error count, status message (audits only — Crawl.statusMessage is not implemented in " +
            "Montoya 2025.10), and for audits the count of issues found so far. To retrieve the actual " +
            "issue details, call the paginated get_scanner_issues tool."
        ) {
            val status = when (val registered = ScanTaskRegistry.get(taskId)) {
                null -> return@mcpTool "Unknown task_id: $taskId"
                is RegisteredScanTask.Audit -> {
                    val audit = registered.task
                    // Burp throws "Currently unsupported." for some accessors while an audit is
                    // still running (statusMessage / insertionPointCount / issues can all throw
                    // pre-completion). Wrap each defensively so partial status still returns
                    // instead of failing the whole tool call.
                    ScanTaskStatus(
                        taskId = registered.id,
                        kind = "AUDIT",
                        requestCount = runCatching { audit.requestCount() }.getOrDefault(0),
                        errorCount = runCatching { audit.errorCount() }.getOrDefault(0),
                        statusMessage = runCatching { audit.statusMessage() }.getOrNull(),
                        insertionPointCount = runCatching { audit.insertionPointCount() }.getOrNull(),
                        issuesFound = runCatching { audit.issues().size }.getOrNull()
                    )
                }
                is RegisteredScanTask.Crawl -> {
                    val crawl = registered.task
                    ScanTaskStatus(
                        taskId = registered.id,
                        kind = "CRAWL",
                        requestCount = runCatching { crawl.requestCount() }.getOrDefault(0),
                        errorCount = runCatching { crawl.errorCount() }.getOrDefault(0)
                    )
                }
            }

            Json.encodeToString(ScanTaskStatus.serializer(), status)
        }

        mcpPaginatedTool<ListScanTasks, ScanTaskSummary>(
            description = "Lists all scan tasks (crawls and audits) currently tracked by the MCP server. " +
                "Tasks are tracked in-memory and do not survive a Burp restart.",
            mapper = { Json.encodeToString(ScanTaskSummary.serializer(), it) }
        ) {
            ScanTaskRegistry.list().map {
                ScanTaskSummary(
                    taskId = it.id,
                    kind = it.kind.name,
                    requestCount = it.task.requestCount(),
                    errorCount = it.task.errorCount()
                )
            }
        }

        mcpTool<CancelScanTask>(
            "Cancels a running scan task and removes it from the registry. If Burp's delete fails, the " +
            "task is left in the registry so it can be retried."
        ) {
            val registered = ScanTaskRegistry.get(taskId)
                ?: return@mcpTool "Unknown task_id: $taskId"

            runCatching { registered.task.delete() }.fold(
                onSuccess = {
                    ScanTaskRegistry.remove(taskId)
                    "Cancelled ${registered.kind} task $taskId"
                },
                onFailure = {
                    api.logging().logToError("Failed to delete scan task $taskId: ${it.message}")
                    "Failed to cancel task $taskId: ${it.message}"
                }
            )
        }

        mcpTool(
            "describe_audit_modes",
            "Describes the two audit modes that start_audit accepts (ACTIVE and PASSIVE), the underlying " +
            "BuiltInAuditConfiguration enum values, and what is NOT configurable from the Montoya API. " +
            "Call this BEFORE start_audit when the user is unclear which mode they want or when you need " +
            "to explain scan behaviour. Pair with get_scanner_configuration to see the project's current " +
            "scanner settings."
        ) {
            buildJsonObject {
                put("ACTIVE", buildJsonObject {
                    put("burpEnumValue", JsonPrimitive("BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS"))
                    put("description", JsonPrimitive(
                        "Burp sends probe payloads (e.g. SQL injection strings, XSS payloads, " +
                        "command injection probes) and inspects responses for vulnerability indicators. " +
                        "Generates new traffic to the target — can be noisy and may trigger WAFs or " +
                        "leave attack-pattern traces in target logs."
                    ))
                    put("noisyToTarget", JsonPrimitive(true))
                    put("typicalDurationHint", JsonPrimitive("minutes to hours depending on target size"))
                })
                put("PASSIVE", buildJsonObject {
                    put("burpEnumValue", JsonPrimitive("BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS"))
                    put("description", JsonPrimitive(
                        "Burp runs passive checks on the seed request/response — no probe payloads " +
                        "are sent, but Burp may fetch resources referenced by the seed (e.g. JS, CSS, " +
                        "images) to inspect them. Detects info-disclosure, missing security headers, " +
                        "weak TLS config, cookie issues, etc. Far quieter than ACTIVE but not zero " +
                        "traffic to the target."
                    ))
                    put("noisyToTarget", JsonPrimitive(false))
                    put("typicalDurationHint", JsonPrimitive("seconds"))
                })
                put("notSupportedByMontoyaApi", buildJsonArray {
                    add(JsonPrimitive("Per-check filtering (e.g. 'only SQLi'). Use Burp UI Settings → Scanner → Scan configurations to define a profile, then it applies to ACTIVE audits."))
                    add(JsonPrimitive("Selecting a named scan configuration via the API."))
                    add(JsonPrimitive("Severity-based pre-filtering. Severity is a property of findings, not checks. Filter results post-scan via get_scanner_issues."))
                })
                put("severityValues", buildJsonArray {
                    listOf("HIGH", "MEDIUM", "LOW", "INFORMATION", "FALSE_POSITIVE").forEach { add(JsonPrimitive(it)) }
                })
                put("seeAlso", buildJsonArray {
                    add(JsonPrimitive("get_scanner_configuration — current Burp scanner project settings"))
                    add(JsonPrimitive("start_audit — launches an audit"))
                    add(JsonPrimitive("get_scanner_issues — paginated list of findings"))
                })
            }.toString()
        }

        mcpTool(
            "get_scanner_configuration",
            "Returns the scanner-relevant slice of the current Burp project options as JSON — what's " +
            "actually configured to run when start_audit is called. Read-only. The exact schema is " +
            "Burp-internal and undocumented; if the expected scanner subtree is not found, the full " +
            "project options JSON is returned with a note. Response is truncated to 5000 chars."
        ) {
            val raw = api.burpSuite().exportProjectOptionsAsJson()
            val parsed = try {
                Json.parseToJsonElement(raw).jsonObject
            } catch (e: Exception) {
                return@mcpTool "Failed to parse project options JSON: ${e.message}\n\n${truncateIfNeeded(raw)}"
            }

            val scannerKeys = listOf("scanner", "proxy")
            val slice = buildJsonObject {
                scannerKeys.forEach { key ->
                    parsed[key]?.let { put(key, it) }
                }
            }

            if (slice.isEmpty()) {
                "No scanner-shaped subtree found in project options under keys ${scannerKeys}. " +
                "Returning full JSON so you can inspect the actual schema:\n\n${truncateIfNeeded(raw)}"
            } else {
                truncateIfNeeded(slice.toString())
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }

    mcpTool<IsInScope>("Checks whether a URL is within Burp's suite-wide target scope.") {
        api.scope().isInScope(url).toString()
    }

    mcpTool<IncludeInScope>(
        "Adds a URL to Burp's suite-wide target scope. Pass a fully-qualified URL or URL prefix " +
        "(e.g. 'https://example.com/'). This API does not accept wildcards or regular expressions; " +
        "use Burp's Target → Scope tab for advanced scope rules. Requires the 'Enable tools that " +
        "can edit your config' setting to be enabled in the MCP tab."
    ) {
        if (!config.configEditingTooling) {
            return@mcpTool toolingDisabledMessage
        }
        api.logging().logToOutput("MCP include_in_scope: $url")
        api.scope().includeInScope(url)
        "Included in scope: $url"
    }

    mcpTool<ExcludeFromScope>(
        "Removes a URL from Burp's suite-wide target scope. Pass a fully-qualified URL or URL " +
        "prefix (e.g. 'https://example.com/'). This API does not accept wildcards or regular " +
        "expressions; use Burp's Target → Scope tab for advanced scope rules. Requires the 'Enable " +
        "tools that can edit your config' setting to be enabled in the MCP tab."
    ) {
        if (!config.configEditingTooling) {
            return@mcpTool toolingDisabledMessage
        }
        api.logging().logToOutput("MCP exclude_from_scope: $url")
        api.scope().excludeFromScope(url)
        "Excluded from scope: $url"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(
    override val count: Int,
    override val offset: Int,
    val host: String? = null,
    val minSeverity: String? = null
) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)

@Serializable
data class SeedRequest(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class StartCrawl(val seedUrls: List<String>)

@Serializable
data class StartAudit(val mode: String, val seedRequest: SeedRequest)

@Serializable
data class AddRequestToAudit(val taskId: String, val request: SeedRequest)

@Serializable
data class GetScanTaskStatus(val taskId: String)

@Serializable
data class ListScanTasks(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class CancelScanTask(val taskId: String)

@Serializable
data class IsInScope(val url: String)

@Serializable
data class IncludeInScope(val url: String)

@Serializable
data class ExcludeFromScope(val url: String)