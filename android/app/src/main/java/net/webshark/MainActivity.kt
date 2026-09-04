package net.webshark

import android.app.Activity
import android.content.Intent
import android.content.res.Configuration
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import android.widget.Toast
import java.io.File
import kotlin.math.roundToInt

/**
 * The whole of the UI: a WebView on the server this app started.
 *
 * Nothing about src/web is Android-specific and nothing here makes it so - every
 * request app.js issues is relative, so pointing a WebView at the loopback
 * address is the entire port. What the shell adds is the two ways a capture gets
 * in, neither of which a page inside a WebView can arrange for itself: the web
 * UI takes an upload by drag-and-drop, and there is no such gesture here, so a
 * capture arrives as an intent instead and is copied into the captures directory
 * the server lists - and the file input the same UI offers opens no chooser
 * unless its embedder opens one for it, which onShowFileChooser below does.
 */
class MainActivity : Activity() {
    companion object {
        private const val TAG = "webshark"
        private const val REQUEST_PICK = 1

        /**
         * What the page's own header bar is painted, reported to [Shell.band].
         *
         * The band left behind the system bars and around a display cutout is
         * meant to read as the page's own edge (see the frame in onCreate, and
         * paint), and which colour that is, is the
         * page's business alone: style.css has a scheme either way and the
         * settings drawer can pin it to one of them, so the device's night
         * setting - all a colour resource out here can see - is at best a guess
         * at it. So the page is asked, and asked for the computed colour of the
         * bar rather than for the theme behind it: what comes back is resolved
         * (rgb(...), whatever the stylesheet wrote) and cannot disagree with
         * what is on screen.
         *
         * Injected rather than added to app.js, which is the same file the UI
         * serves to a browser and has nothing else Android about it. It reports
         * once for the page it lands in, and again on either thing that decides
         * the scheme: the drawer's data-theme on <html>, and - for the theme
         * that follows the system - the media query it follows.
         */
        private const val WATCH = """
            (function () {
              const bar = document.querySelector('header')
              if (!bar) return
              const tell = () => shell.band(getComputedStyle(bar).backgroundColor)
              if (!window.__bandwatch) {
                window.__bandwatch = true
                new MutationObserver(tell).observe(document.documentElement,
                    { attributeFilter: ['data-theme'] })
                matchMedia('(prefers-color-scheme: dark)').addEventListener('change', tell)
              }
              tell()
            })()
        """
    }

    private lateinit var web: WebView
    private lateinit var frame: FrameLayout   // what carries the insets
    // What the page said its header bar is painted, or null until it has said -
    // see WATCH. Main thread only, as everything below it is.
    private var band: Int? = null
    // What the navigation bar covers of the bottom edge, in the page's own
    // pixels - see foot(). Zero until the insets have been dispatched, which is
    // also what it is on a device that reserves nothing there.
    private var nav = 0
    // Both are the main thread's alone, which is what makes the handover below
    // safe without anything guarding it.
    private var loaded = false            // the page is up and app.js is in it
    private var pending: String? = null   // a capture that arrived before it was
    // ...and so is this: a chooser is opened and answered on the main thread and
    // nowhere else.
    private var chooser: ValueCallback<Array<Uri>>? = null

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)

        // The service owns the server process; see ServerService for why the
        // server is not simply started here.
        startService(Intent(this, ServerService::class.java))

        // A notch or hole-punch is a physically opaque part of the screen, and
        // the system only lets a window's content extend under it at all if
        // asked; ALWAYS is R+, SHORT_EDGES is the 28-29 equivalent (it only
        // covers portrait, but every cutout device this old is a portrait notch
        // anyway, and in landscape it letterboxes the window off the cutout
        // whatever the frame below then asks for).
        //
        // Asked for because in portrait what ends up under it is not the page:
        // the notch is inside the strip the status bar already costs, and what
        // is in that strip is the band. Landscape is the one place it would
        // cost an edge of its own, and there the page is given it instead -
        // see the frame.
        window.attributes = window.attributes.apply {
            layoutInDisplayCutoutMode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS
            else
                WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES
        }

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
                    // ...and the page can be asked what colour it is now,
                    // which is what the band around it is painted, and told
                    // what the navigation bar costs it at the bottom - a page
                    // that has just replaced the one that was told knows
                    // nothing of either.
                    view.evaluateJavascript(WATCH, null)
                    foot()
                    pending?.let { pending = null; show(it) }
                }
            }

            // The footer's "click to choose" is an <input type=file>, and a
            // WebView opens a chooser for one only if its embedder does - so
            // without this the tap on it was silently nothing, and the drop the
            // same footer offers instead is not a gesture a phone has. What is
            // chosen goes back to the page, which uploads it over the loopback
            // exactly as a browser would: the upload is app.js's either way, and
            // only the picking of the file needs anything from out here.
            webChromeClient = object : WebChromeClient() {
                override fun onShowFileChooser(
                    view: WebView, callback: ValueCallback<Array<Uri>>,
                    params: FileChooserParams
                ): Boolean {
                    // One answer per callback, and no chooser is offered again
                    // until the last one has had it - so a chooser somehow still
                    // outstanding is cancelled rather than left to wedge the
                    // input, and a picker that will not open is answered here.
                    chooser?.onReceiveValue(null)
                    chooser = callback
                    try {
                        startActivityForResult(params.createIntent(), REQUEST_PICK)
                    } catch (err: Exception) {
                        Log.e(TAG, "no app to choose a capture with", err)
                        chooser = null
                        callback.onReceiveValue(null)
                    }
                    return true
                }
            }

            // The only thing this app adds to the page's own world, and one
            // method wide. Nothing else can reach it: every document the
            // WebView loads is served by this app over loopback (see
            // network_security_config.xml) and a link to anywhere else has
            // left for a browser above.
            addJavascriptInterface(Shell(), "shell")
        }

        // What the system has already taken out of the screen - the status
        // bar, the navigation bar, a display cutout - the page has no way to
        // ask about: the bars are not its business at all and the cutout is
        // native geometry, not something env(safe-area-inset-*) sees inside a
        // WebView. So it is met out here rather than by any change to src/web:
        // the page renders exactly as it always has, in a WebView inset from
        // whatever is not free for it to draw in.
        //
        // The window itself draws behind all of it (see paint) rather than
        // being fitted to it, and this frame is what keeps the page out from
        // under three of the four edges.
        //
        // The inset is padding on a frame around the WebView and not on the
        // WebView itself: a WebView's own padding moves its scrollbars and
        // nothing else - the page is laid out and painted across the whole of
        // the view's bounds either way - so the strip the system costs has to
        // come out of the space the WebView is given instead. Which leaves the
        // frame showing in that strip, hence its colour: the page's own header
        // bar, so the band the clock sits in reads as the top of that bar.
        // Which colour that is, the page says as soon as there is one (see
        // WATCH); until then the resource, which is the same guess index.html
        // makes before its own first paint and wrong only for a theme the
        // drawer has pinned.
        //
        // Three edges, but at the sides only what the bars cost there. A cutout
        // at a side is landscape's - a hole a few pixels down one long edge -
        // and a band the whole height of the screen to clear it is the worse
        // trade of the two: the page loses a strip of the packet list to the
        // camera, which is a corner of a table, and keeps the width. So the
        // sides clear the bars and nothing else, and the top - where a notch
        // is either inside the status bar's strip or a little taller than it -
        // clears whichever of the two reaches further.
        //
        // The bottom is not inset, and is the one edge nothing out here paints:
        // the page runs to it and the navigation bar sits on the footer's own
        // colour, which is the whole of what "transparent" can mean for a bar
        // over an app's own window. All that is needed for that is that nothing
        // the footer holds ends up under the gesture area, which is the page's
        // to arrange and not this frame's - so the strip is handed over as a
        // length instead of taken away as padding. See foot().
        frame = FrameLayout(this).apply {
            setBackgroundColor(getColor(R.color.band))
            addView(web, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
            setOnApplyWindowInsetsListener { view, insets ->
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // The bars alone for the sides, the union of the two for
                    // the top and the bottom, which is where a cutout is ever
                    // asked to be cleared.
                    val bars = insets.getInsets(WindowInsets.Type.systemBars())
                    val room = insets.getInsets(
                        WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                    view.setPadding(bars.left, room.top, bars.right, 0)
                    foot(room.bottom)
                } else {
                    // Pre-R they are two separate numbers per edge and the
                    // wider is the one that clears both. The bars' half is only
                    // reported at all because of the LAYOUT_ flags in paint;
                    // the cutout is API 28, which is every version this runs on.
                    // Its side insets are dropped here too, though SHORT_EDGES
                    // above means there is never anything in them to drop.
                    val cutout = insets.displayCutout
                    @Suppress("DEPRECATION")
                    view.setPadding(
                        insets.systemWindowInsetLeft,
                        maxOf(insets.systemWindowInsetTop, cutout?.safeInsetTop ?: 0),
                        insets.systemWindowInsetRight,
                        0)
                    @Suppress("DEPRECATION")
                    foot(maxOf(insets.systemWindowInsetBottom, cutout?.safeInsetBottom ?: 0))
                }
                insets
            }
        }
        setContentView(frame)
        // mDecor exists once setContentView returns, but PhoneWindow reads its
        // insets controller off the decor view's ViewRootImpl, which only
        // exists once the window is attached - WindowManager.addView(), which
        // happens after onResume() returns, not here. Calling paint() this
        // early throws a NullPointerException on launch; the attach listener is
        // what runs it once that is actually true.
        window.decorView.addOnAttachStateChangeListener(object : View.OnAttachStateChangeListener {
            override fun onViewAttachedToWindow(v: View) {
                v.removeOnAttachStateChangeListener(this)
                paint()
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

    /** The other half of onShowFileChooser: whatever was picked, handed to the
     *  input that asked for it. */
    override fun onActivityResult(request: Int, result: Int, data: Intent?) {
        super.onActivityResult(request, result, data)
        if (request != REQUEST_PICK) return
        val callback = chooser ?: return
        chooser = null
        // parseResult() answers null for a cancel and for anything it cannot
        // read, which is the answer the input wants either way - it is what
        // leaves it able to ask again.
        callback.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(result, data))
    }

    /**
     * Back, which on a phone is the whole of the navigation: the gesture (or the
     * button, where there is one) is the only way out of a view, the header
     * offering one button for one step of it and nothing for the rest.
     *
     * So the page is asked first, and asked for one level and not for the way
     * out: pop() in app.js closes whatever is on top - the frame's dissection,
     * then the capture - and answers whether there was anything to close, which
     * is what decides between going back and leaving. It can only be asked
     * asynchronously, hence the callback; back is not animated here (predictive
     * back is opt-in and this does not opt in), so nothing waits visibly on it.
     */
    override fun onBackPressed() {
        web.evaluateJavascript("typeof pop === 'function' && pop()") { closed ->
            if (closed != "true") leave()
        }
    }

    /** Out of the app, which is what back means with nothing left to close. The
     *  WebView's own history is not consulted: the page keeps its whole state in
     *  the fragment and replaces rather than pushes it (see sync() in app.js), so
     *  the only entries there are this app's loads - going back to one would put
     *  a URL on a view pop() has already left. */
    private fun leave() = super.onBackPressed()

    /**
     * The band, and what the system draws on top of it.
     *
     * The window is edge-to-edge but not fullscreen: the bars stay where they
     * are - the clock, the notification shade and the navigation are the
     * phone's and not an app's to take away - and what the window claims is
     * only the right to paint underneath them. What is behind the status bar
     * and a cutout is the band, in the page's own header colour, the frame in
     * onCreate keeping the page itself out of that strip; what is behind the
     * navigation bar is the page, which runs to the bottom edge and holds its
     * footer clear of the gesture area itself (see foot()). Both come out the
     * same colour - style.css paints the footer the header's - so the band is
     * what either bar's icons have to be legible on.
     *
     * Which leaves their icons, the one thing out here that has to stay legible
     * against that band. The system draws them either light or dark on request,
     * so the request follows the band's brightness - and not the device's night
     * setting, which is a different question: the band is the page's colour and
     * the settings drawer can pin the page to a scheme the device is not in.
     *
     * No AndroidX here (see build.gradle.kts), so pre-R this is the flags
     * WindowInsetsController replaced. What makes the bars transparent, so that
     * the band shows through them at all, is neither: it is the theme's, the
     * two colours that would say it in code being no-ops from API 35 on (see
     * themes.xml).
     */
    private fun paint() {
        val color = band ?: getColor(R.color.band)
        frame.setBackgroundColor(color)
        // Relative luminance, which is what "how dark is this colour" means to
        // everyone who has had to answer it; half way is where it turns over.
        val pale = Color.luminance(color) > 0.5f
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.setDecorFitsSystemWindows(false)
            // "Light bars" is the system's name for what it draws over a light
            // background, which is dark icons.
            val light = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
            window.insetsController?.apply {
                show(WindowInsets.Type.systemBars())
                setSystemBarsAppearance(if (pale) light else 0, light)
            }
        } else {
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = (
                // Laid out as if neither bar were there, which is both what
                // puts the band behind them and what makes the listener in
                // onCreate hear how much room they take...
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                // ...and none of FULLSCREEN, HIDE_NAVIGATION or IMMERSIVE with
                // them, which is what would take the bars themselves away.
                or (if (pale) View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
                        or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR else 0)
            )
        }
        // Both branches change what the window's insets are, and the frame's
        // padding is only ever set from a dispatch of them - R+ re-dispatches on
        // its own when the decor stops fitting them, the flags do not.
        window.decorView.requestApplyInsets()
    }

    /**
     * What the navigation bar costs the bottom edge, told to the page.
     *
     * That edge is the page's own: the frame in onCreate insets the other three
     * and leaves this one alone, so the page runs under the navigation bar and
     * the bar sits on the footer rather than on a strip painted out here. Which
     * is what makes it transparent in the only sense an app can offer - there
     * is nothing behind a bar but the app's own window - and it is also the
     * only version of it worth having: a band in the footer's colour and the
     * footer itself are the same thing to look at, right up to the moment they
     * disagree about what that colour is.
     *
     * What the page has to do about it is keep the footer's contents out of the
     * strip: it is a bar that can be tapped (the capture list's file picker
     * hangs off it) and the bottom of the screen belongs to the back gesture,
     * so a footer laid out into it is a footer that cannot be used. Only the
     * page knows what it has put there, hence a length handed over rather than
     * padding imposed: style.css adds it to the footer's own bottom padding,
     * which leaves the footer's background - not this - painting the strip.
     *
     * In CSS pixels, which is dp: a WebView at initial-scale=1 puts one CSS
     * pixel on one of them, so the number the insets report is divided by the
     * display density and nothing else has to be agreed with the page.
     *
     * Called with the inset when it is dispatched, and with nothing when a page
     * that has not heard it needs it again (see onPageFinished).
     */
    private fun foot(px: Int? = null) {
        px?.let { nav = (it / resources.displayMetrics.density).roundToInt() }
        // A page that is not up yet is told by onPageFinished instead; there is
        // no document to set a property on before that.
        if (loaded) web.evaluateJavascript(
            "document.documentElement.style.setProperty('--nav', '${nav}px')", null)
    }

    override fun onConfigurationChanged(config: Configuration) {
        super.onConfigurationChanged(config)
        // uiMode is one of the activity's configChanges, so a switch into dark
        // mode arrives here rather than as a restart. Only the colour the band
        // has before the page has spoken follows the device: after that it is
        // the page's header colour, and the page reports a new one itself if the
        // scheme under it changed too (see WATCH).
        paint()
    }

    override fun onDestroy() {
        // The service owns the server; leaving it running is what lets the
        // capture stay loaded across a rotation or a trip to another app.
        (web.parent as? ViewGroup)?.removeView(web)
        web.destroy()
        super.onDestroy()
    }

    /**
     * What WATCH talks to: the colour of the page's header bar, which is what
     * the band a cutout leaves is painted so that the band reads as the top of
     * it whatever the page's theme is.
     */
    private inner class Shell {
        @JavascriptInterface
        fun band(css: String) {
            val color = colorOf(css) ?: return
            // A method reached from JavaScript runs on the WebView's own thread,
            // and a view may only be touched on the one that made it.
            runOnUiThread {
                this@MainActivity.band = color
                paint()
            }
        }
    }

    /** A colour as the page computed it - rgb(r, g, b), or rgba() with an alpha
     *  this has no use for, which is how a colour any of style.css's schemes
     *  writes comes back - or null for anything that is neither, which leaves
     *  the band as it was rather than painting it a colour read out of noise. */
    private fun colorOf(css: String): Int? {
        val channels = Regex("\\d+").findAll(css).map { it.value.toInt() }.take(3).toList()
        if (channels.size < 3) return null
        return Color.rgb(channels[0].coerceIn(0, 255), channels[1].coerceIn(0, 255),
            channels[2].coerceIn(0, 255))
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

    /** Puts a capture on screen in a page that is already loaded, by naming it
     *  in the fragment the page keeps its whole state in - see sync() in app.js.
     *  A load is what reads that, and neither of these quite is one: an
     *  identical URL is no navigation at all, hence the reload, and a fragment
     *  that differs navigates within the same document, re-running nothing. */
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
