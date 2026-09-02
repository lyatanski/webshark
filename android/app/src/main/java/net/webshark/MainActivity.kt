package net.webshark

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.util.Log
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import java.io.File

/**
 * The whole of the UI: a WebView on the server this app started.
 *
 * Nothing about src/web is Android-specific and nothing here makes it so - every
 * request app.js issues is relative, so pointing a WebView at the loopback
 * address is the entire port. What the shell adds is the one thing a phone has no
 * answer for: the web UI takes an upload by drag-and-drop, and there is no such
 * gesture here, so a capture arrives as an intent instead and is copied into the
 * captures directory the server lists.
 */
class MainActivity : Activity() {
    companion object {
        private const val TAG = "webshark"
        private const val PERMISSION_NOTIFICATIONS = 1
    }

    private lateinit var web: WebView
    // Both are the main thread's alone, which is what makes the handover below
    // safe without anything guarding it.
    private var loaded = false            // the page is up and app.js is in it
    private var pending: String? = null   // a capture that arrived before it was

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)

        // Only so the foreground-service notification is visible; the service
        // runs either way, and nothing here waits for an answer.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),
                PERMISSION_NOTIFICATIONS)
        }

        startForegroundService(Intent(this, ServerService::class.java))

        web = WebView(this).apply {
            settings.javaScriptEnabled = true
            // app.js keeps the chosen theme in localStorage, and index.html reads
            // it back before first paint; without this that read throws.
            settings.domStorageEnabled = true
            settings.textZoom = 100
            // Everything is served from 127.0.0.1 and nothing else is reachable
            // (see network_security_config.xml), so anything that is not the
            // server is a link the user meant to open elsewhere.
            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(
                    view: WebView, request: WebResourceRequest
                ): Boolean {
                    val url = request.url
                    if (url.host == Server.HOST && url.port == Server.PORT) return false
                    startActivity(Intent(Intent.ACTION_VIEW, url))
                    return true
                }

                // Not when the load was asked for: a capture is put on screen by
                // changing the fragment, and app.js only hears that once it has
                // run and subscribed. Between the two it would be lost.
                override fun onPageFinished(view: WebView, url: String) {
                    loaded = true
                    pending?.let { pending = null; show(it) }
                }
            }
        }
        setContentView(web)
        // mDecor exists once setContentView returns, but PhoneWindow reads its
        // insets controller off the decor view's ViewRootImpl, which only
        // exists once the window is attached - WindowManager.addView(), which
        // happens after onResume() returns, not here. Calling hideSystemBars()
        // this early throws a NullPointerException on launch; the attach
        // listener is what runs it once that is actually true, and
        // onWindowFocusChanged() below keeps it applied after that.
        window.decorView.addOnAttachStateChangeListener(object : View.OnAttachStateChangeListener {
            override fun onViewAttachedToWindow(v: View) {
                v.removeOnAttachStateChangeListener(this)
                hideSystemBars()
            }
            override fun onViewDetachedFromWindow(v: View) {}
        })

        // The copy and the wait for the server need nothing from each other,
        // so they run at once and whichever finishes last puts the capture on
        // screen. Waiting for the copy before loading anything would be a blank
        // window for as long as the capture is big.
        take(intent)
        open()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // singleTask, so a capture shared into an app that is already running
        // arrives here rather than in a second activity - and takes exactly the
        // route the one the app was started with took.
        take(intent)
    }

    override fun onBackPressed() {
        if (web.canGoBack()) web.goBack() else super.onBackPressed()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        // A swipe from the edge, or a trip to another app and back, brings the
        // bars back on its own; there is no callback for that, only this.
        if (hasFocus) hideSystemBars()
    }

    /** Status and navigation bars both, swipeable back in from either edge for
     *  as long as it takes to use them. No AndroidX here (see build.gradle.kts),
     *  so pre-R this falls back to the flags WindowInsetsController replaced. */
    private fun hideSystemBars() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.setDecorFitsSystemWindows(false)
            window.insetsController?.apply {
                hide(WindowInsets.Type.systemBars())
                systemBarsBehavior = WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
            }
        } else {
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = (
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_FULLSCREEN
                or View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
            )
        }
    }

    override fun onDestroy() {
        // The service owns the server; leaving it running is what lets the
        // capture stay loaded across a rotation or a trip to another app.
        (web.parent as? android.view.ViewGroup)?.removeView(web)
        web.destroy()
        super.onDestroy()
    }

    /** Copies whatever an intent carries in, off the main thread because a
     *  capture is as big as it is, and shows it - or leaves it for the page to
     *  pick up, if there is not one yet. */
    private fun take(intent: Intent?) {
        Thread {
            val taken = importFrom(intent).firstOrNull() ?: return@Thread
            runOnUiThread { if (loaded) show(taken) else pending = taken }
        }.apply { isDaemon = true }.start()
    }

    /** The server binds its port only once it is ready to answer, so this waits
     *  for that rather than for a fixed time. */
    private fun open() {
        Thread {
            val up = Server.awaitReady(30_000)
            runOnUiThread {
                if (up) {
                    // If the copy already finished this is the capture, and if it
                    // did not this is the list and onPageFinished will have it.
                    web.loadUrl(urlFor(pending))
                    pending = null
                } else {
                    Toast.makeText(this, R.string.server_failed, Toast.LENGTH_LONG).show()
                }
            }
        }.apply { isDaemon = true }.start()
    }

    /**
     * Where in the web UI a capture is. The whole of that UI's state lives in the
     * fragment - see sync() in app.js - so naming a file there is what opens it
     * instead of the list, and is the difference between the app having been
     * handed a capture and the capture being open.
     */
    private fun urlFor(name: String?): String =
        if (name == null) Server.URL else Server.URL + "#f=" + Uri.encode(name)

    /** Puts a capture on screen in a page that is already loaded. Only the
     *  fragment differs, which is not a navigation: app.js listens for
     *  hashchange and reopens on it, but an identical URL changes nothing and
     *  so fires nothing - re-opening the capture already showing is a reload. */
    private fun show(name: String) {
        val url = urlFor(name)
        if (web.url == url) web.reload() else web.loadUrl(url)
    }

    /**
     * Copies whatever a VIEW or SEND intent carries into the captures directory,
     * and answers with the names it wrote.
     *
     * A copy and not a reference: the server reads captures by name out of one
     * directory, and a content:// URI is neither a name nor readable by the child
     * process holding it - the permission is this app's and does not survive
     * being handed to sharkd.
     */
    @Suppress("DEPRECATION") // the typed getParcelableExtra is API 33, minSdk is 28
    private fun importFrom(intent: Intent?): List<String> {
        val uris = when (intent?.action) {
            Intent.ACTION_VIEW -> listOfNotNull(intent.data)
            Intent.ACTION_SEND ->
                listOfNotNull(intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM))
            Intent.ACTION_SEND_MULTIPLE ->
                intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM) ?: emptyList()
            else -> emptyList()
        }

        val taken = mutableListOf<String>()
        for (uri in uris) {
            try {
                val target = File(Server.capturesDir(this), nameOf(uri))
                contentResolver.openInputStream(uri)?.use { source ->
                    target.outputStream().use { source.copyTo(it) }
                } ?: continue
                Log.i(TAG, "imported ${target.name}, ${target.length()} bytes")
                taken += target.name
            } catch (err: Exception) {
                Log.e(TAG, "import failed: $uri", err)
                runOnUiThread { Toast.makeText(this, err.message, Toast.LENGTH_LONG).show() }
            }
        }
        return taken
    }

    /**
     * A file name the server will list. It validates one itself - a bare name,
     * no separators, no leading dot (see nameOK in src/main.go) - so anything a
     * provider hands back that would not pass is replaced rather than sent on to
     * be rejected.
     */
    private fun nameOf(uri: Uri): String {
        var name: String? = null
        if (uri.scheme == "content") {
            contentResolver.query(uri, null, null, null, null)?.use { row ->
                val column = row.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (column >= 0 && row.moveToFirst()) name = row.getString(column)
            }
        }
        val candidate = (name ?: uri.lastPathSegment ?: "capture")
            .substringAfterLast('/')
            .replace(Regex("[^A-Za-z0-9 ._+-]"), "_")
            .trimStart('.')
            .take(128)
        return if (candidate.isEmpty()) "capture-${System.currentTimeMillis()}.pcap" else candidate
    }
}
