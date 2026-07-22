package com.buildin1.phantom_p2p

import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class LogStore(context: Context) {

    private val logDir: File = File(context.filesDir, "logs")
    private val logFile: File = File(logDir, "phantom-android.log")
    private val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())

    init {
        if (!logDir.exists()) {
            logDir.mkdirs()
        }
        if (!logFile.exists()) {
            logFile.createNewFile()
        }
    }

    @Synchronized
    fun append(level: String, module: String, text: String) {
        rotateIfNeeded()
        val line = "${dateFmt.format(Date())} [$level][$module] $text\n"
        logFile.appendText(line)
    }

    fun path(): String = logFile.absolutePath

    @Synchronized
    fun readTailLines(maxLines: Int = 200): String {
        if (!logFile.exists()) return ""
        val lines = logFile.readLines()
        if (lines.size <= maxLines) return lines.joinToString("\n")
        return lines.takeLast(maxLines).joinToString("\n")
    }

    @Synchronized
    private fun rotateIfNeeded(maxBytes: Long = 2L * 1024 * 1024) {
        if (!logFile.exists()) return
        if (logFile.length() <= maxBytes) return

        val backup = File(logDir, "phantom-android.log.1")
        if (backup.exists()) {
            backup.delete()
        }
        logFile.copyTo(backup, overwrite = true)
        logFile.writeText("")
    }
}
