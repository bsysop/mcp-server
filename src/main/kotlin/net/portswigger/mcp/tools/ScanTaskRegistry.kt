package net.portswigger.mcp.tools

import burp.api.montoya.scanner.ScanTask
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import burp.api.montoya.scanner.Crawl as MontoyaCrawl
import burp.api.montoya.scanner.audit.Audit as MontoyaAudit

enum class ScanTaskKind { CRAWL, AUDIT }

sealed class RegisteredScanTask {
    abstract val id: String
    abstract val task: ScanTask

    val kind: ScanTaskKind
        get() = when (this) {
            is Crawl -> ScanTaskKind.CRAWL
            is Audit -> ScanTaskKind.AUDIT
        }

    data class Crawl(override val id: String, override val task: MontoyaCrawl) : RegisteredScanTask()
    data class Audit(override val id: String, override val task: MontoyaAudit) : RegisteredScanTask()
}

object ScanTaskRegistry {
    private val tasks = ConcurrentHashMap<String, RegisteredScanTask>()

    fun register(crawl: MontoyaCrawl): String {
        val id = UUID.randomUUID().toString()
        tasks[id] = RegisteredScanTask.Crawl(id, crawl)
        return id
    }

    fun register(audit: MontoyaAudit): String {
        val id = UUID.randomUUID().toString()
        tasks[id] = RegisteredScanTask.Audit(id, audit)
        return id
    }

    fun get(id: String): RegisteredScanTask? = tasks[id]

    fun remove(id: String): RegisteredScanTask? = tasks.remove(id)

    fun list(): List<RegisteredScanTask> = tasks.values.toList()

    fun clear() = tasks.clear()
}
