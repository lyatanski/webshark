package net.webshark

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log

/**
 * Holds the server process, so that the capture survives leaving the app.
 *
 * A running service is what puts the process above an empty one in what Android
 * kills first: with nothing but a backgrounded activity, the app is stopped
 * about as soon as it leaves the screen and the server goes with it, so every
 * return would be a restart and a reload of whatever capture was open.
 *
 * A plain service and not a foreground one, which is the trade this makes: a
 * foreground service is the only thing that survives indefinitely out of sight,
 * and its price is a permanent notification. So the process keeps service
 * priority for as long as Android lets a backgrounded app keep it - minutes,
 * not forever - which covers the trip to a file manager or a chat the capture
 * came out of, and nothing here fights the eventual kill.
 */
class ServerService : Service() {
    companion object {
        private const val TAG = "webshark"
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Off the main thread: this unpacks the asset tree and forks a process,
        // and onStartCommand is where an ANR comes from.
        Thread {
            try {
                Server.start(this)
            } catch (err: Exception) {
                Log.e(TAG, "server did not start", err)
                stopSelf()
            }
        }.apply { isDaemon = true }.start()
        // Not sticky: the activity starts this in onCreate, so returning to the
        // app is what brings the server back. Restarting it behind a stopped
        // activity would be a server nobody is reading, killed again for the
        // same reason it was killed the first time.
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        Server.stop()
        super.onDestroy()
    }
}
