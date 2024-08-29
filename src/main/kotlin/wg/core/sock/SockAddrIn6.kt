package wg.core.sock

import com.sun.jna.Structure
import com.sun.jna.platform.win32.WinDef.USHORT
import com.sun.jna.platform.win32.WinDef.ULONG

class SockAddrIn6 : Structure() {
    @JvmField
    var sin6_family: USHORT = USHORT(0)  // Address family (AF_INET6)

    @JvmField
    var sin6_port: USHORT = USHORT(0)  // Port number

    @JvmField
    var sin6_flowinfo: ULONG = ULONG(0)  // IPv6 flow information

    @JvmField
    var sin6_addr: ByteArray = ByteArray(16)  // IPv6 address (in network byte order)

    @JvmField
    var sin6_scope_id: ULONG = ULONG(0)  // Scope ID

    override fun getFieldOrder(): List<String> {
        return listOf("sin6_family", "sin6_port", "sin6_flowinfo", "sin6_addr", "sin6_scope_id")
    }
}