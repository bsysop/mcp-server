package net.portswigger.mcp.tools

import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.audit.Audit
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ScanTaskRegistryTest {

    @AfterEach
    fun cleanup() {
        ScanTaskRegistry.clear()
    }

    @Test
    fun `register returns a unique id and stores the task with the right kind`() {
        val crawl = mockk<Crawl>(relaxed = true)
        val audit = mockk<Audit>(relaxed = true)

        val id1 = ScanTaskRegistry.register(crawl)
        val id2 = ScanTaskRegistry.register(audit)

        assertNotNull(id1)
        assertNotNull(id2)
        assertNotEquals(id1, id2)

        val r1 = ScanTaskRegistry.get(id1)
        val r2 = ScanTaskRegistry.get(id2)
        assertNotNull(r1)
        assertNotNull(r2)
        assertTrue(r1 is RegisteredScanTask.Crawl)
        assertTrue(r2 is RegisteredScanTask.Audit)
        assertEquals(ScanTaskKind.CRAWL, r1!!.kind)
        assertEquals(ScanTaskKind.AUDIT, r2!!.kind)
        assertEquals(crawl, (r1 as RegisteredScanTask.Crawl).task)
        assertEquals(audit, (r2 as RegisteredScanTask.Audit).task)
    }

    @Test
    fun `get returns null for unknown id`() {
        assertNull(ScanTaskRegistry.get("nonexistent-id"))
    }

    @Test
    fun `remove returns the registered task and subsequent get returns null`() {
        val crawl = mockk<Crawl>(relaxed = true)
        val id = ScanTaskRegistry.register(crawl)

        val removed = ScanTaskRegistry.remove(id)
        assertNotNull(removed)
        assertTrue(removed is RegisteredScanTask.Crawl)
        assertEquals(crawl, (removed as RegisteredScanTask.Crawl).task)
        assertNull(ScanTaskRegistry.get(id))
    }

    @Test
    fun `remove returns null for unknown id`() {
        assertNull(ScanTaskRegistry.remove("nonexistent-id"))
    }

    @Test
    fun `list returns all registered tasks`() {
        val crawl = mockk<Crawl>(relaxed = true)
        val audit1 = mockk<Audit>(relaxed = true)
        val audit2 = mockk<Audit>(relaxed = true)

        ScanTaskRegistry.register(crawl)
        ScanTaskRegistry.register(audit1)
        ScanTaskRegistry.register(audit2)

        val all = ScanTaskRegistry.list()
        assertEquals(3, all.size)
        assertTrue(all.any { it is RegisteredScanTask.Crawl && it.task == crawl })
        assertTrue(all.any { it is RegisteredScanTask.Audit && it.task == audit1 })
        assertTrue(all.any { it is RegisteredScanTask.Audit && it.task == audit2 })
    }

    @Test
    fun `clear removes everything`() {
        ScanTaskRegistry.register(mockk<Crawl>(relaxed = true))
        ScanTaskRegistry.register(mockk<Audit>(relaxed = true))

        ScanTaskRegistry.clear()

        assertEquals(0, ScanTaskRegistry.list().size)
    }

    @Test
    fun `register does not invoke any methods on the task`() {
        val crawl = mockk<Crawl>(relaxed = true)
        ScanTaskRegistry.register(crawl)

        verify(exactly = 0) { crawl.delete() }
        verify(exactly = 0) { crawl.requestCount() }
    }

    @Test
    fun `concurrent registers from many coroutines yield unique ids and consistent state`() {
        val n = 200

        runBlocking {
            coroutineScope {
                repeat(n) {
                    launch {
                        if (it % 2 == 0) {
                            ScanTaskRegistry.register(mockk<Crawl>(relaxed = true))
                        } else {
                            ScanTaskRegistry.register(mockk<Audit>(relaxed = true))
                        }
                    }
                }
            }
        }

        val all = ScanTaskRegistry.list()
        assertEquals(n, all.size, "Every concurrent register must produce a registry entry")
        assertEquals(n, all.map { it.id }.toSet().size, "IDs must be unique across concurrent registers")
        val crawls = all.count { it is RegisteredScanTask.Crawl }
        val audits = all.count { it is RegisteredScanTask.Audit }
        assertEquals(n / 2, crawls)
        assertEquals(n / 2, audits)
    }
}
