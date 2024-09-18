package wg

import com.sun.jna.Memory
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WTypes
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.platform.win32.WinError
import com.sun.jna.ptr.IntByReference
import wg.core.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

class WireguardImplementation(
    private val callback: WireGuardInterface? = null
): WireGuardLoggerCallback {

    private val manager = WireGuardManager()

    fun connectConfig(
        iflags: IoctlInterfaceFlags = IoctlInterfaceFlags.HAS_PRIVATE_KEY,
        ilistenPort: Short,
        iprivateKey: ByteArray,
        ipublicKey: ByteArray? = null,
        ipeerCount: Int = 1,
        pflags: IoctlPeerFlags = IoctlPeerFlags.HAS_ENDPOINT,
        ppublicKey: ByteArray,
        ppreshared: ByteArray? = null,
        ppersistent: Int = 45,
        pendpoint: String,
        dns: List<String>
    ) {
        setDNSForWireGuardAdapter(WireGuardManager.NAME, dns)

        // Example call to configure the interface
        val interfaze = configureInterface(iflags, ilistenPort, iprivateKey, ipublicKey, ipeerCount)

        // Convert endpoint string to socket address
        val sockAddrInet = pendpoint.toSocketAddress() ?: run {
            println("Error: Unrecognized socket address")
            return
        }

        // Example call to configure the peer
        val peer = configurePeer(pflags, ppublicKey, ppreshared, ppersistent, sockAddrInet)

        // Example call to establish the connection
        connectConfig(interfaze, peer)
    }

    fun connectConfig(interfaze: IoctlInterface, peerConfig: IoctlWgPeerConfig) {
        setConfig(interfaze, peerConfig)
        connect()
    }

    private fun setConfig(interfaze: IoctlInterface, peerConfig: IoctlWgPeerConfig) {
        val config = IoctlWireGuardConfig()
        config.interfaze = interfaze
        config.wgPeerConfigs = arrayOf(peerConfig)
        manager.setConfiguration(config)

        getConfig()
    }

    fun connect() {
        manager.apply {
            openAdapter {
                callback?.onMessage("Creating Adapter")
                createAdapter(
                    onSuccess = ::establishConnection,
                    onFailed = {
                        callback?.onError(it)
                    }
                )
            }
        }
    }

    private fun establishConnection() {
        callback?.onMessage("Establishing Connection")
        manager.apply {
            setAdapterLogging(WireGuardAdapterLoggerLevel.WIREGUARD_LOG_ON)
            setLogger(this@WireguardImplementation)

            setAdapterState(WireGuardAdapterState.WIREGUARD_ADAPTER_STATE_UP)
        }
    }

    fun disconnect() {
        manager.setAdapterState(WireGuardAdapterState.WIREGUARD_ADAPTER_STATE_DOWN)
    }

    fun version() = manager.driverVersion()
    fun getState() {
        manager.getAdapterState {
            callback?.onMessage(it.toString())
        }
    }

    fun getConfig(
        bufferSize: Int = 1024
    ) {
        val bytesRef = IntByReference(bufferSize)
        val configMemory = Memory(bufferSize.toLong()) // Allocate memory for configuration

        val retryResult = manager.getConfiguration(
            configMemory,
            bytesRef
        )

        if (retryResult) {
            val errorCode = Kernel32.INSTANCE.GetLastError()

            if (errorCode == WinError.ERROR_MORE_DATA) {
                getConfig(bytesRef.value)
            } else {
                throw RuntimeException("Failed to get WireGuard configuration. Error code: $errorCode")
            }
        } else {
            println("WireGuard configuration retrieved successfully.")
//            callback?.onConfiguration(
//                parseConfiguration(configMemory).toStringDetailed()
//            )

        }
    }

    fun configureInterface(
        iflags: IoctlInterfaceFlags = IoctlInterfaceFlags.DEFAULT,
        ilistenPort: Short,
        iprivateKey: ByteArray,
        ipublicKey: ByteArray? = null,
        ipeerCount: Int = 1
    ): IoctlInterface {
        return IoctlInterface().apply {
            flags = iflags.value
            listenPort = ilistenPort.toUShort()
            privateKey = iprivateKey
            publicKey = ipublicKey ?: ByteArray(32) // Initialize with 32 bytes if null
            peersCount = ipeerCount.toUInt()
        }
    }

    fun configurePeer(
        iflags: IoctlPeerFlags = IoctlPeerFlags.DEFAULT,
        ipublicKey: ByteArray,
        ipreshared: ByteArray? = null,
        ipersistent: Int,
        iendpoint: SOCKADDR_INET,
    ): IoctlWgPeerConfig {
        return IoctlWgPeerConfig().apply {
            allowedIp
            client = IoctlPeer().apply {
                flags = iflags.value
                reserved = 0.toUInt()
                publicKey = ipublicKey
                ipreshared?.let {
                    presharedKey = it
                }
                persistentKeepalive = ipersistent.toUShort()
                endpoint = iendpoint
                txBytes = 1024.toULong()
                rxBytes = 1024.toULong()
            }
        }
    }

    private fun String.toSocketAddress(): SOCKADDR_INET? {
        val sockAddr = SOCKADDR_INET()
        val inetAddr = InetAddress.getByName(this.substringBefore(":"))
        return if (inetAddr.address.size == 4)
            sockAddr.apply {
                si_family = 2
                Ipv4.s_addr = inetAddr.address.fold(0) { acc, byte ->
                    (acc shl 8) or (byte.toInt() and 0xFF)
                }
            }
        else if (inetAddr.address.size == 16)
            sockAddr.apply {
                si_family = 23
                Ipv6.Byte = inetAddr.address
            }
        else
            null
    }


    override fun invoke(level: UInt, timestamp: WinDef.DWORD, message: WTypes.LPWSTR) {
        val levelStr = when (level) {
            WireGuardLoggerLevel.WIREGUARD_LOG_INFO.value -> "INFO"
            WireGuardLoggerLevel.WIREGUARD_LOG_WARN.value -> "WARN"
            WireGuardLoggerLevel.WIREGUARD_LOG_ERROR.value -> "ERROR"
            else -> "Unknown"
        }
        val messageStr = message.toString()
        println("[$levelStr] $timestamp: $messageStr")
    }

    companion object {

        fun setDNSForWireGuardAdapter(adapterName: String, dnsServers: List<String>) {
            try {
                // Build the netsh command to set DNS servers
                dnsServers.forEachIndexed { index, dnsServer ->
                    val command = if (index == 0) {
                        "netsh interface ip set dns name=\"$adapterName\" static $dnsServer"
                    } else {
                        "netsh interface ip add dns name=\"$adapterName\" $dnsServer"
                    }

                    // Execute the command
                    val process = Runtime.getRuntime().exec(command)
                    val reader = BufferedReader(InputStreamReader(process.inputStream))
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        println(line)
                    }
                    process.waitFor()
                }
                println("DNS settings updated for $adapterName")
            } catch (e: Exception) {
                println("Failed to set DNS: ${e.message}")
            }
        }
    }
}