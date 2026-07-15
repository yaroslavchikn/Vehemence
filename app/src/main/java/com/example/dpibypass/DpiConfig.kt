package com.example.dpibypass

object DpiConfig {
    var enableTlsFragment = true
    var enableSniObfuscation = true
    var enableFakePackets = true
    var enableHttpObfuscation = true
    var enableTtlTrick = true
    
    var fragmentSize = 100
    var fragmentDelay = 10
    var fakePacketCount = 3
    var fakePacketSize = 64
    var sniPrefix = "www."
    var sniSuffix = ".example.com"
    
    val youtubeDomains = setOf(
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "youtu.be",
        "googlevideo.com",
        "ytimg.com",
        "youtube.googleapis.com",
        "yt3.ggpht.com",
        "i.ytimg.com"
    )
    
    fun isYoutubeTraffic(host: String): Boolean {
        return youtubeDomains.any { host.contains(it, ignoreCase = true) }
    }
}
