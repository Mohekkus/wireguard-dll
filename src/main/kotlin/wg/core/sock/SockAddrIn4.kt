package wg.core.sock

import com.sun.jna.Structure
import com.sun.jna.platform.win32.WinDef.USHORT

class SockAddrIn4 : Structure() {
    @JvmField
    var sin_family: USHORT = USHORT(0)  // Address family (AF_INET)

    @JvmField
    var sin_port: USHORT = USHORT(0)  // Port number

    @JvmField
    var sin_addr: ByteArray = ByteArray(4)  // IPv4 address (in network byte order)

    @JvmField
    var sin_zero: ByteArray = ByteArray(8)  // Padding to match the size of SOCKADDR_IN

    override fun getFieldOrder(): List<String> {
        return listOf("sin_family", "sin_port", "sin_addr", "sin_zero")
    }
}