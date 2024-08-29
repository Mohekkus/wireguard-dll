package wg.core.sock

import com.sun.jna.Union
import com.sun.jna.platform.win32.WinDef.USHORT

class SockAddrInet: Union() {
    @JvmField
    var Ipv4: SockAddrIn4 = SockAddrIn4()

    @JvmField
    var Ipv6: SockAddrIn6 = SockAddrIn6()

    @JvmField
    var si_family: USHORT = USHORT(0)

    override fun getFieldOrder(): List<String> {
        return listOf("Ipv4", "Ipv6", "si_family")
    }
}