package com.example.dpibypass

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DpiVpnService : VpnService() {
    
    companion object {
        private const val TAG = "DpiVpnService"
        private const val CHANNEL_ID = "dpi_bypass_channel"
        private const val NOTIFICATION_ID = 1
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_MTU = 1500
    }
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private val packetProcessor = PacketProcessor()
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startVpn()
        return START_STICKY
    }
    
    private fun startVpn() {
        if (isRunning) {
            Log.d(TAG, "VPN already running")
            return
        }
        
        try {
            // Настраиваем VPN-интерфейс
            val builder = Builder()
            builder.setSession("DPI Bypass")
            builder.addAddress(VPN_ADDRESS, 32)
            builder.addRoute("0.0.0.0", 0) // Весь трафик через VPN
            builder.setMtu(VPN_MTU)
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            
            vpnInterface = builder.establish()
            isRunning = true
            
            Log.i(TAG, "VPN started successfully")
            
            // Запускаем обработку пакетов
            serviceScope.launch {
                processPackets()
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN: ${e.message}")
            isRunning = false
        }
    }
    
    private suspend fun processPackets() {
        val fd = vpnInterface ?: return
        val inputStream = FileInputStream(fd.fileDescriptor)
        val outputStream = FileOutputStream(fd.fileDescriptor)
        
        val packetBuffer = ByteBuffer.allocate(VPN_MTU)
        packetBuffer.order(ByteOrder.BIG_ENDIAN)
        
        while (isRunning) {
            try {
                // Читаем пакет из VPN-интерфейса
                val bytesRead = inputStream.read(packetBuffer.array())
                if (bytesRead <= 0) continue
                
                packetBuffer.clear()
                packetBuffer.limit(bytesRead)
                
                // Определяем направление трафика
                // Для простоты считаем все пакеты исходящими
                val isOutgoing = true
                
                // Обрабатываем пакет
                val processedPacket = packetProcessor.processPacket(packetBuffer, isOutgoing)
                
                if (processedPacket != null) {
                    // Отправляем обработанный пакет
                    outputStream.write(processedPacket.array(), 0, processedPacket.limit())
                    outputStream.flush()
                }
                // Если processedPacket == null — пакет отбрасываем
                
            } catch (e: Exception) {
                if (isRunning) {
                    Log.e(TAG, "Error processing packets: ${e.message}")
                }
            }
        }
    }
    
    override fun onDestroy() {
        isRunning = false
        serviceScope.cancel()
        vpnInterface?.close()
        vpnInterface = null
        super.onDestroy()
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "DPI Bypass Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("DPI Bypass")
            .setContentText("Активен — обход блокировок")
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
}
