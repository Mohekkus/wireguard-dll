package wg

import com.sun.jna.platform.win32.WTypes
import com.sun.jna.platform.win32.WinDef
import kotlinx.coroutines.delay
import wg.core.*
import java.net.InetAddress

class WireguardImplementation(
    private val callback: WireGuardInterface? = null
): WireGuardLoggerCallback {

    private val manager = WireGuardManager().apply {
        addEnviromentalVariable()
    }

    fun connectConfig(
        iflags: IoctlInterfaceFlags = IoctlInterfaceFlags.DEFAULT,
        ilistenPort: Short,
        iprivateKey: ByteArray,
        ipublicKey: ByteArray? = null,
        ipeerCount: Int = 1,
        pflags: IoctlPeerFlags = IoctlPeerFlags.DEFAULT,
        ppublicKey: ByteArray,
        ppreshared: ByteArray? = null,
        ppersistent: Int = 45,
        pendpoint: String,
    ) {
        val interfaze = configureInterface(iflags, ilistenPort, iprivateKey, ipublicKey, ipeerCount)
        val sockAddrInet = pendpoint.toSocketAddress() ?: run {
            callback?.onError("Unrecognized socket address")
            return
        }
        val peer = configurePeer(pflags, ppublicKey, ppreshared, ppersistent, sockAddrInet)
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
    }



    fun connect() {
        manager.apply {
            openAdapter {
                callback?.onMessage("Creating Adapter")
                createAdapter {
                    callback?.onError("Cannot create nor opening adapter")
                }
            }
            setAdapterLogging(WireGuardAdapterLoggerLevel.WIREGUARD_LOG_ON)
            setLogger(this@WireguardImplementation)

            setAdapterState(WireGuardAdapterState.WIREGUARD_ADAPTER_STATE_UP)
        }
    }

    fun disconnect() {
        manager.closeAdapter {

        }
    }

    fun version() = manager.driverVersion()
    fun configureInterface(
        iflags: IoctlInterfaceFlags = IoctlInterfaceFlags.DEFAULT,
        ilistenPort: Short,
        iprivateKey: ByteArray,
        ipublicKey: ByteArray?,
        ipeerCount: Int = 1
    ): IoctlInterface {
        return IoctlInterface().apply {
            flags = iflags.value
            listenPort = ilistenPort.toUShort()
            privateKey = iprivateKey
            ipublicKey?.let {
                publicKey = it
            }
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
}