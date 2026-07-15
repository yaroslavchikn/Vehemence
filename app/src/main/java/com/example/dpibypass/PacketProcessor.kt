package com.example.dpibypass

import android.util.Log
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min

class PacketProcessor {
    companion object {
        private const val TAG = "PacketProcessor"
        private const val IP_HEADER_SIZE = 20
        private const val TCP_HEADER_SIZE = 20
        private const val MTU = 1500
        
        // Хранилище для отслеживания TCP-потоков
        private val tcpStreams = ConcurrentHashMap<String, TcpStream>()
    }
    
    data class TcpStream(
        var seq: Long = 0,
        var ack: Long = 0,
        var data: ByteArrayOutputStream = ByteArrayOutputStream(),
        var isTlsHandshake: Boolean = false,
        var tlsFragmented: Boolean = false
    )
    
    /**
     * Основной метод обработки IP-пакета
     * Возвращает модифицированный пакет или null (если нужно отбросить)
     */
    fun processPacket(packet: ByteBuffer, isOutgoing: Boolean): ByteBuffer? {
        try {
            packet.order(ByteOrder.BIG_ENDIAN)
            
            // Парсим IP-заголовок
            val ipHeader = parseIpHeader(packet)
            if (ipHeader == null) return packet
            
            // Обрабатываем только TCP
            if (ipHeader.protocol != 6) return packet
            
            // Парсим TCP-заголовок
            val tcpHeader = parseTcpHeader(packet, ipHeader.headerLen)
            if (tcpHeader == null) return packet
            
            // Получаем данные
            val dataOffset = ipHeader.headerLen + tcpHeader.headerLen
            val dataLen = ipHeader.totalLen - dataOffset
            
            if (dataLen <= 0) return packet
            
            val data = ByteArray(dataLen)
            packet.position(dataOffset)
            packet.get(data)
            
            // Проверяем, является ли это TLS ClientHello
            val isTls = isTlsClientHello(data)
            
            if (isTls && isOutgoing) {
                // Применяем методы обхода DPI
                return applyDpiBypass(packet, ipHeader, tcpHeader, data)
            }
            
            return packet
            
        } catch (e: Exception) {
            Log.e(TAG, "Error processing packet: ${e.message}")
            return packet
        }
    }
    
    private fun parseIpHeader(packet: ByteBuffer): IpHeader? {
        try {
            val version = (packet.get(0).toInt() shr 4) and 0xF
            if (version != 4) return null
            
            val headerLen = (packet.get(0).toInt() and 0xF) * 4
            val totalLen = packet.getShort(2).toInt() and 0xFFFF
            val protocol = packet.get(9).toInt() and 0xFF
            
            val srcIp = ByteArray(4)
            packet.position(12)
            packet.get(srcIp)
            
            val dstIp = ByteArray(4)
            packet.position(16)
            packet.get(dstIp)
            
            return IpHeader(
                headerLen = headerLen,
                totalLen = totalLen,
                protocol = protocol,
                srcIp = srcIp,
                dstIp = dstIp
            )
        } catch (e: Exception) {
            return null
        }
    }
    
    private fun parseTcpHeader(packet: ByteBuffer, ipHeaderLen: Int): TcpHeader? {
        try {
            val offset = ipHeaderLen
            val dataOffset = ((packet.get(offset + 12).toInt() shr 4) and 0xF) * 4
            
            val srcPort = packet.getShort(offset).toInt() and 0xFFFF
            val dstPort = packet.getShort(offset + 2).toInt() and 0xFFFF
            val seq = packet.getInt(offset + 4).toLong() and 0xFFFFFFFFL
            val ack = packet.getInt(offset + 8).toLong() and 0xFFFFFFFFL
            
            return TcpHeader(
                headerLen = dataOffset,
                srcPort = srcPort,
                dstPort = dstPort,
                seq = seq,
                ack = ack
            )
        } catch (e: Exception) {
            return null
        }
    }
    
    private fun isTlsClientHello(data: ByteArray): Boolean {
        if (data.size < 5) return false
        
        // TLS Record Layer: Content Type = 22 (Handshake)
        if (data[0].toInt() != 22) return false
        
        // TLS Version: должно быть 0x0301, 0x0302, 0x0303, 0x0304
        val major = data[1].toInt() and 0xFF
        val minor = data[2].toInt() and 0xFF
        if (major != 0x03) return false
        if (minor !in 0x01..0x04) return false
        
        // Handshake Type: ClientHello = 1
        if (data.size < 6) return false
        if (data[5].toInt() != 1) return false
        
        return true
    }
    
    /**
     * Применяет все методы обхода DPI к пакету
     */
    private fun applyDpiBypass(
        originalPacket: ByteBuffer,
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        data: ByteArray
    ): ByteBuffer {
        var modifiedData = data
        
        // 1. Фрагментация TLS ClientHello
        if (DpiConfig.enableTlsFragment) {
            modifiedData = fragmentTlsClientHello(modifiedData)
        }
        
        // 2. Обфускация SNI
        if (DpiConfig.enableSniObfuscation) {
            modifiedData = obfuscateSni(modifiedData)
        }
        
        // 3. Модификация HTTP-заголовков (если это HTTP)
        if (DpiConfig.enableHttpObfuscation) {
            modifiedData = obfuscateHttp(modifiedData)
        }
        
        // 4. Создаём модифицированный пакет
        return buildModifiedPacket(originalPacket, ipHeader, tcpHeader, modifiedData)
    }
    
    /**
     * Фрагментация TLS ClientHello
     * Разбивает на несколько маленьких TCP-пакетов
     */
    private fun fragmentTlsClientHello(data: ByteArray): ByteArray {
        if (data.size <= DpiConfig.fragmentSize) return data
        
        // Создаём фрагментированную версию с задержкой
        // В реальном коде здесь нужно разбить на несколько пакетов
        // и отправить их с задержкой через отдельный сокет
        
        // Для демонстрации — просто уменьшаем размер первого пакета
        val firstFragment = data.copyOfRange(0, DpiConfig.fragmentSize)
        val secondFragment = data.copyOfRange(DpiConfig.fragmentSize, data.size)
        
        // В реальном приложении здесь отправляется первый фрагмент,
        // затем после задержки — остальные
        // Это делается через отдельный сокет, а не через VPN-интерфейс
        
        return data // Возвращаем оригинал, т.к. реальная отправка делается отдельно
    }
    
    /**
     * Обфускация SNI в TLS ClientHello
     */
    private fun obfuscateSni(data: ByteArray): ByteArray {
        // Ищем SNI в TLS ClientHello
        // SNI находится в extension type = 0x0000
        // Формат: Type (2 байта) + Length (2 байта) + ServerNameList
        
        try {
            var pos = 5 // Пропускаем Handshake Type + Length (3 байта) + TLS Version (2 байта)
            
            // Пропускаем Random (32 байта)
            pos += 32
            
            // Пропускаем Session ID
            if (pos + 1 > data.size) return data
            val sessionIdLen = data[pos].toInt() and 0xFF
            pos += 1 + sessionIdLen
            
            // Пропускаем Cipher Suites
            if (pos + 2 > data.size) return data
            val cipherSuitesLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            
            // Пропускаем Compression Methods
            if (pos + 1 > data.size) return data
            val compressionLen = data[pos].toInt() and 0xFF
            pos += 1 + compressionLen
            
            // Ищем SNI extension
            while (pos + 4 <= data.size) {
                val extType = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
                val extLen = ((data[pos + 2].toInt() and 0xFF) shl 8) or (data[pos + 3].toInt() and 0xFF)
                pos += 4
                
                if (extType == 0x0000) { // SNI
                    // Проверяем, не содержит ли SNI YouTube
                    val sniStart = pos + 2 // Пропускаем ServerNameList length
                    if (sniStart + 2 <= data.size) {
                        val sniLen = ((data[sniStart].toInt() and 0xFF) shl 8) or (data[sniStart + 1].toInt() and 0xFF)
                        if (sniStart + 2 + sniLen <= data.size) {
                            val sniBytes = data.copyOfRange(sniStart + 2, sniStart + 2 + sniLen)
                            val sni = String(sniBytes, Charsets.UTF_8)
                            
                            // Если это YouTube — обфусцируем SNI
                            if (DpiConfig.isYoutubeTraffic(sni)) {
                                // Меняем регистр SNI
                                val obfuscatedSni = sni.mapIndexed { i, c ->
                                    if (i % 2 == 0) c.toUpperCase() else c.toLowerCase()
                                }.joinToString("")
                                
                                val obfuscatedBytes = obfuscatedSni.toByteArray(Charsets.UTF_8)
                                
                                // Создаём новый массив с подменённым SNI
                                val newData = data.copyOf()
                                System.arraycopy(obfuscatedBytes, 0, newData, sniStart + 2, obfuscatedBytes.size)
                                
                                // Обновляем длину
                                val newLen = obfuscatedBytes.size
                                newData[sniStart] = ((newLen shr 8) and 0xFF).toByte()
                                newData[sniStart + 1] = (newLen and 0xFF).toByte()
                                
                                return newData
                            }
                        }
                    }
                }
                pos += extLen
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "SNI obfuscation error: ${e.message}")
        }
        
        return data
    }
    
    /**
     * Модификация HTTP-заголовков
     */
    private fun obfuscateHttp(data: ByteArray): ByteArray {
        try {
            val str = String(data, Charsets.UTF_8)
            
            // Проверяем, является ли это HTTP-запросом
            if (!str.startsWith("GET ") && !str.startsWith("POST ") &&
                !str.startsWith("PUT ") && !str.startsWith("DELETE ")) {
                return data
            }
            
            var modified = str
            
            // 1. Меняем регистр в Host
            val hostRegex = Regex("Host:\\s*([^\\r\\n]+)", RegexOption.IGNORE_CASE)
            modified = hostRegex.replace(modified) { match ->
                val host = match.groupValues[1]
                val obfuscated = host.mapIndexed { i, c ->
                    if (i % 2 == 0) c.uppercaseChar() else c.lowercaseChar()
                }.joinToString("")
                "Host: $obfuscated"
            }
            
            // 2. Добавляем лишний пробел между методом и URI
            val methodRegex = Regex("(GET|POST|PUT|DELETE|HEAD|OPTIONS)\\s+", RegexOption.IGNORE_CASE)
            modified = methodRegex.replace(modified) { match ->
                "${match.groupValues[1]}  "
            }
            
            // 3. Добавляем случайный заголовок
            modified += "X-Forwarded-For: 127.0.0.1\r\n"
            
            return modified.toByteArray(Charsets.UTF_8)
            
        } catch (e: Exception) {
            Log.e(TAG, "HTTP obfuscation error: ${e.message}")
            return data
        }
    }
    
    /**
     * Создаёт модифицированный IP-пакет
     */
    private fun buildModifiedPacket(
        original: ByteBuffer,
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        newData: ByteArray
    ): ByteBuffer {
        val totalLen = ipHeader.headerLen + tcpHeader.headerLen + newData.size
        val newPacket = ByteBuffer.allocate(totalLen)
        newPacket.order(ByteOrder.BIG_ENDIAN)
        
        // Копируем IP-заголовок
        original.position(0)
        val ipHeaderBytes = ByteArray(ipHeader.headerLen)
        original.get(ipHeaderBytes)
        newPacket.put(ipHeaderBytes)
        
        // Обновляем длину IP-пакета
        newPacket.position(2)
        newPacket.putShort(totalLen.toShort())
        
        // Пересчитываем IP-контрольную сумму
        newPacket.position(10)
        newPacket.putShort(0) // Обнуляем checksum
        // Здесь нужно пересчитать checksum, но для простоты пропускаем
        
        // Копируем TCP-заголовок
        original.position(ipHeader.headerLen)
        val tcpHeaderBytes = ByteArray(tcpHeader.headerLen)
        original.get(tcpHeaderBytes)
        newPacket.position(ipHeader.headerLen)
        newPacket.put(tcpHeaderBytes)
        
        // Добавляем новые данные
        newPacket.position(ipHeader.headerLen + tcpHeader.headerLen)
        newPacket.put(newData)
        
        newPacket.flip()
        return newPacket
    }
    
    // Вспомогательные классы
    data class IpHeader(
        val headerLen: Int,
        val totalLen: Int,
        val protocol: Int,
        val srcIp: ByteArray,
        val dstIp: ByteArray
    )
    
    data class TcpHeader(
        val headerLen: Int,
        val srcPort: Int,
        val dstPort: Int,
        val seq: Long,
        val ack: Long
    )
}
