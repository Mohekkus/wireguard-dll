package wg.core

import com.sun.jna.FromNativeContext
import com.sun.jna.Structure
import com.sun.jna.Structure.FieldOrder
import com.sun.jna.Pointer
import com.sun.jna.ToNativeContext
import com.sun.jna.ptr.ByteByReference
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.*

class Key(bytes: ByteArray) {
    var bytes: ByteArray = bytes
        set(value) {
            require(value.size == 32) { "Keys must be 32 bytes" }
            field = value
        }

    init {
        this.bytes = bytes
    }

    constructor(bytes: Pointer) : this(bytes.getByteArray(0, 32))

    override fun toString(): String {
        return Base64.getEncoder().encodeToString(bytes)
    }
}

data class WGInterface(
    var listenPort: UShort,
    var privateKey: Key,
    var publicKey: Key,
    var peers: Array<WGPeer>
)

data class WGPeer(
    var publicKey: Key,
    var presharedKey: Key,
    var persistentKeepalive: UShort,
    var endpoint: InetSocketAddress,
    var txBytes: ULong,
    var rxBytes: ULong,
    var lastHandshake: Date,
    var allowedIPs: Array<AllowedIP>
)

data class AllowedIP(
    var address: InetAddress,
    var cidr: Byte
)

enum class IoctlInterfaceFlags(val value: UInt) {
    DEFAULT(0u),
    HAS_PUBLIC_KEY(1u shl 0),
    HAS_PRIVATE_KEY(1u shl 1),
    HAS_LISTEN_PORT(1u shl 2),
    REPLACE_PEERS(1u shl 3)
}

@FieldOrder("privateKey", "publicKey")
open class IoctlInterface : Structure() {
    var flags: UInt = 0u            // WIREGUARD_INTERFACE_FLAG
    var listenPort: UShort = 0u     // WORD
    @JvmField var privateKey = ByteArray(32)  // BYTE array of length WIREGUARD_KEY_LENGTH
    @JvmField var publicKey = ByteArray(32)   // BYTE array of length WIREGUARD_KEY_LENGTH
    var peersCount: UInt = 0u       // DWORD

    // Inner classes to represent references and values
    class ByReference : IoctlInterface(), Structure.ByReference
    class ByValue : IoctlInterface(), Structure.ByValue
}

enum class IoctlPeerFlags(val value: UInt) {
    DEFAULT(0u),
    HAS_PUBLIC_KEY(1u shl 0),
    HAS_PRESHARED_KEY(1u shl 1),
    HAS_PERSISTENT_KEEPALIVE(1u shl 2),
    HAS_ENDPOINT(1u shl 3),
    REPLACE_ALLOWED_IPS(1u shl 5),
    REMOVE(1u shl 6),
    UPDATE_ONLY(1u shl 7)
}

@FieldOrder(
    "publicKey",
    "presharedKey",
    "endpoint",
)
open class IoctlPeer : Structure() {
    var flags: UInt = 0u
    var reserved: UInt = 0u
    @JvmField var publicKey = ByteArray(32)
    @JvmField var presharedKey = ByteArray(32)
    var persistentKeepalive: UShort = 0u
    @JvmField var endpoint = SOCKADDR_INET()
    var txBytes: ULong = 0uL
    var rxBytes: ULong = 0uL
    var lastHandshake: ULong = 0uL
    var allowedIPsCount: UInt = 0u

    class ByReference : IoctlPeer(), Structure.ByReference
    class ByValue : IoctlPeer(), Structure.ByValue
}

@FieldOrder("si_family", "Ipv4", "Ipv6", "Padding")
open class SOCKADDR_INET : Structure() {
    @JvmField var si_family: Short = 0  // Corresponding to ADDRESS_FAMILY, typically AF_INET or AF_INET6
    @JvmField var Ipv4 = IN_ADDR()      // Union, for IPv4
    @JvmField var Ipv6 = IN6_ADDR()     // Union, for IPv6
    @JvmField var Padding = ByteArray(112) // Pad to match expected size

    class ByReference : SOCKADDR_INET(), Structure.ByReference
    class ByValue : SOCKADDR_INET(), Structure.ByValue
}

@FieldOrder("v4", "v6", "addressFamily", "cidr")
open class IoctlAllowedIP : Structure() {
    @JvmField var v4 = IN_ADDR() // Implement IN_ADDR according to your needs
    @JvmField var v6 = IN6_ADDR() // Implement IN6_ADDR according to your needs
    @JvmField var addressFamily: Short = 0 // Corresponding type to ADDRESS_FAMILY
    @JvmField var cidr: Byte = 0

    class ByReference : IoctlAllowedIP(), Structure.ByReference
    class ByValue : IoctlAllowedIP(), Structure.ByValue
}

@FieldOrder("s_addr")
open class IN_ADDR : Structure() {
    @JvmField var s_addr: Int = 0 // Represents IPv4 address as a 32-bit integer

    class ByReference : IN_ADDR(), Structure.ByReference
    class ByValue : IN_ADDR(), Structure.ByValue
}

@FieldOrder("Byte")
open class IN6_ADDR : Structure() {
    @JvmField var Byte = ByteArray(16) // Represents IPv6 address as a 16-byte array

    class ByReference : IN6_ADDR(), Structure.ByReference
    class ByValue : IN6_ADDR(), Structure.ByValue
}

@FieldOrder("interfaze", "wgPeerConfigs")
open class IoctlWireGuardConfig : Structure() {
    @JvmField var interfaze = IoctlInterface()
    @JvmField var wgPeerConfigs: Array<IoctlWgPeerConfig> = arrayOf()

    class ByReference : IoctlWireGuardConfig(), Structure.ByReference
    class ByValue : IoctlWireGuardConfig(), Structure.ByValue
}

@FieldOrder("client", "allowedIp")
open class IoctlWgPeerConfig : Structure() {
    @JvmField var client = IoctlPeer()
    @JvmField var allowedIp = IoctlAllowedIP()

    class ByReference : IoctlWgPeerConfig(), Structure.ByReference
    class ByValue : IoctlWgPeerConfig(), Structure.ByValue
}

enum class WireGuardAdapterState(val value: Int) {
    WIREGUARD_ADAPTER_STATE_DOWN(0),
    WIREGUARD_ADAPTER_STATE_UP(1)
}

enum class WireGuardLoggerLevel(val value: UInt) {
    WIREGUARD_LOG_INFO(0u),
    WIREGUARD_LOG_WARN(1u),
    WIREGUARD_LOG_ERROR(2u)
}


// Define a custom type converter for WireGuardLoggerLevel
class WireGuardLoggerLevelConverter : com.sun.jna.TypeConverter {

    override fun fromNative(p0: Any?, p1: FromNativeContext?): Any {
        return WireGuardLoggerLevel.values().find { it.value.toInt() == (p0 as Int) }
            ?: throw IllegalArgumentException("Unknown value: $p0")
    }

    override fun nativeType(): Class<*> {
        return WireGuardLoggerLevel::class.java
    }

    override fun toNative(p0: Any?, p1: ToNativeContext?): Any {
        return (p0 as WireGuardLoggerLevel).value.toInt()
    }
}

enum class WireGuardAdapterLoggerLevel(val value: Int) {
    WIREGUARD_LOG_OFF(0),
    WIREGUARD_LOG_ON(1),
    WIREGUARD_LOG_ON_PREFIX(2)
}
