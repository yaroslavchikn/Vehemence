package com.example.dpibypass

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
    private lateinit var fragmentSwitch: Switch
    private lateinit var sniSwitch: Switch
    private lateinit var httpSwitch: Switch
    
    private var isRunning = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
        
        initViews()
        setupListeners()
        updateStatus()
    }

    private fun initViews() {
        statusText = findViewById(R.id.statusText)
        startButton = findViewById(R.id.startButton)
        stopButton = findViewById(R.id.stopButton)
        fragmentSwitch = findViewById(R.id.fragmentSwitch)
        sniSwitch = findViewById(R.id.sniSwitch)
        httpSwitch = findViewById(R.id.httpSwitch)
        
        // Загружаем настройки
        fragmentSwitch.isChecked = DpiConfig.enableTlsFragment
        sniSwitch.isChecked = DpiConfig.enableSniObfuscation
        httpSwitch.isChecked = DpiConfig.enableHttpObfuscation
    }

    private fun setupListeners() {
        startButton.setOnClickListener {
            startVpn()
        }
        
        stopButton.setOnClickListener {
            stopVpn()
        }
        
        fragmentSwitch.setOnCheckedChangeListener { _, isChecked ->
            DpiConfig.enableTlsFragment = isChecked
            Toast.makeText(this, "Фрагментация: ${if (isChecked) "вкл" else "выкл"}", Toast.LENGTH_SHORT).show()
        }
        
        sniSwitch.setOnCheckedChangeListener { _, isChecked ->
            DpiConfig.enableSniObfuscation = isChecked
            Toast.makeText(this, "Обфускация SNI: ${if (isChecked) "вкл" else "выкл"}", Toast.LENGTH_SHORT).show()
        }
        
        httpSwitch.setOnCheckedChangeListener { _, isChecked ->
            DpiConfig.enableHttpObfuscation = isChecked
            Toast.makeText(this, "Модификация HTTP: ${if (isChecked) "вкл" else "выкл"}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun startVpn() {
        if (isRunning) {
            Toast.makeText(this, "Уже запущено", Toast.LENGTH_SHORT).show()
            return
        }

        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, 1)
        } else {
            onActivityResult(1, RESULT_OK, null)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == RESULT_OK) {
            val vpnIntent = Intent(this, DpiVpnService::class.java)
            startService(vpnIntent)
            isRunning = true
            updateStatus()
            Toast.makeText(this, "🚀 DPI Bypass запущен", Toast.LENGTH_SHORT).show()
        }
    }

    private fun stopVpn() {
        if (!isRunning) {
            Toast.makeText(this, "Уже остановлен", Toast.LENGTH_SHORT).show()
            return
        }
        val vpnIntent = Intent(this, DpiVpnService::class.java)
        stopService(vpnIntent)
        isRunning = false
        updateStatus()
        Toast.makeText(this, "⛔ DPI Bypass остановлен", Toast.LENGTH_SHORT).show()
    }

    private fun updateStatus() {
        statusText.text = if (isRunning) "🟢 Активен" else "🔴 Остановлен"
        statusText.setTextColor(
            if (isRunning) 
                resources.getColor(android.R.color.holo_green_dark, null)
            else 
                resources.getColor(android.R.color.holo_red_dark, null)
        )
        startButton.isEnabled = !isRunning
        stopButton.isEnabled = isRunning
    }
}
