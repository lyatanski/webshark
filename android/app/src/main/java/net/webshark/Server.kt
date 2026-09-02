package net.webshark

import android.content.Context
import android.util.Log
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * The webshark server, as a child process.
 *
 * There is no Android in webshark itself and none is wanted: the same binary the
 * container runs is started here with the same environment variables, and every
 * path it would find under /usr on a Linux box is named explicitly instead. Two
 * of those are Wireshark's rather than webshark's - WIRESHARK_DATA_DIR and
 * WIRESHARK_PLUGIN_DIR - and they are inherited by every sharkd the server
 * spawns, which is how the preferences, the coloring rules, the dissector data
 * files Wireshark ships (the Diameter dictionaries, the DTDs and the rest) and
 * ims.lua reach it.
 */
object Server {
    private const val TAG = "webshark"

    /** Loopback only. Nothing else on the device has any business reading the
     *  captures, and an unqualified port would be reachable by all of it. */
    const val HOST = "127.0.0.1"
    const val PORT = 8085
    const val URL = "http://$HOST:$PORT/"

    @Volatile private var process: Process? = null

    @Synchronized
    fun start(ctx: Context) {
        if (process?.isAlive == true) return

        val home = ctx.filesDir
        val libs = ctx.applicationInfo.nativeLibraryDir
        val captures = capturesDir(ctx)

        install(ctx, home)
        File(home, "config").mkdirs()

        val server = File(libs, "libwebshark.so")
        if (!server.canExecute()) {
            // Almost always one thing: the APK was built without
            // extractNativeLibs, so nothing was unpacked to a place that can be
            // executed. See the packaging block in app/build.gradle.kts.
            throw IllegalStateException("${server.path} is not executable")
        }

        val builder = ProcessBuilder(server.path).redirectErrorStream(true)
        builder.environment().apply {
            put("CAPTURES", captures.path)
            put("LISTEN", "$HOST:$PORT")
            put("SHARKD", File(libs, "libsharkd.so").path)
            // A phone is not a server: sharkd holds a whole dissected capture in
            // memory and the low-memory killer does not care that it is a child
            // process, so one at a time, dropped sooner, and a shorter scan.
            put("SHARKD_SESSIONS", "1")
            put("SHARKD_IDLE", "120")
            put("SCAN_FRAMES", "2000")

            // Where /usr/local/share/wireshark would be, and the plugin
            // directory the main Dockerfile sets to the same purpose.
            put("WIRESHARK_DATA_DIR", File(home, "share").path)
            put("WIRESHARK_PLUGIN_DIR", File(home, "plugins").path)
            // Wireshark writes into its personal configuration directory; there
            // is no passwd entry to derive one from here, so it is named. HOME
            // is what it would otherwise fall back to, and is set for anything
            // that reaches for it directly.
            put("WIRESHARK_CONFIG_DIR", File(home, "config").path)
            put("HOME", home.path)
            put("TMPDIR", ctx.cacheDir.path)
        }

        Log.i(TAG, "starting ${server.path}, captures in ${captures.path}")
        val started = builder.start()
        process = started

        // The server logs to stderr and sharkd's own diagnostics go the same
        // way; redirectErrorStream put both on stdout, and this puts them where
        // they can be read.
        Thread {
            started.inputStream.bufferedReader().forEachLine { Log.i(TAG, it) }
        }.apply { isDaemon = true }.start()
    }

    /**
     * Ending the server ends the sharkd processes with it, and nothing here has
     * to know their pids: each of them is talked to over a pipe this process
     * holds, and sharkd exits when that pipe reaches EOF - which is the same
     * thing session.close() in src/sharkd.go relies on.
     */
    @Synchronized
    fun stop() {
        process?.destroy()
        process = null
    }

    /** Where captures live. App-specific external storage, so it needs no
     *  permission and survives as long as the app does. */
    fun capturesDir(ctx: Context): File =
        File(ctx.getExternalFilesDir(null) ?: ctx.filesDir, "captures").apply { mkdirs() }

    /**
     * Waits for the server to answer, which is the only honest way to know it is
     * up: it binds the port after it has read its environment and its captures
     * directory, and anything that went wrong went wrong before that.
     */
    fun awaitReady(timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (process?.isAlive == false) return false
            try {
                Socket().use { it.connect(InetSocketAddress(HOST, PORT), 200); return true }
            } catch (_: Exception) {
                Thread.sleep(100)
            }
        }
        return false
    }

    /**
     * Unpacks the asset tree into filesDir - Wireshark's data directory with
     * webshark's preferences and coloring rules over it, and ims.lua, all of it
     * staged by Dockerfile.android.
     *
     * Rewritten on every start rather than once: it is 4 MB over a few hundred
     * files and this already runs off the main thread (see ServerService), which
     * is cheaper than what skipping it costs - a stale dictionary or preferences
     * file after an upgrade is a bug nobody would think to look for.
     */
    private fun install(ctx: Context, into: File) {
        fun copy(path: String) {
            val names = ctx.assets.list(path) ?: emptyArray()
            if (names.isEmpty()) {
                val target = File(into, path)
                target.parentFile?.mkdirs()
                ctx.assets.open(path).use { source ->
                    target.outputStream().use { source.copyTo(it) }
                }
                return
            }
            for (name in names) copy(if (path.isEmpty()) name else "$path/$name")
        }
        for (top in listOf("share", "plugins")) copy(top)
    }
}
