package net.webshark

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log

/**
 * Holds the server process for as long as the app is meant to be usable.
 *
 * Without this the process is the activity's: Android stops a backgrounded app
 * and the server goes with it, so every return to the app would be a restart and
 * a reload of whatever capture was open. A foreground service is what says
 * otherwise, and the notification is the price Android charges for it.
 */
class ServerService : Service() {
    companion object {
        private const val TAG = "webshark"
        private const val CHANNEL = "server"
        private const val NOTIFICATION = 1
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION, notification())
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
        // START_STICKY would have Android restart this with a null intent after
        // a kill, which is what is wanted: the activity is still there to be
        // returned to and it expects a server behind it.
        return START_STICKY
    }

    override fun onDestroy() {
        Server.stop()
        super.onDestroy()
    }

    private fun notification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.service_channel),
                NotificationManager.IMPORTANCE_LOW)
        )
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.service_running))
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }
}
