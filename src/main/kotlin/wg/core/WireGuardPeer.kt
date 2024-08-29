package wg.core

import com.sun.jna.NativeLong
import com.sun.jna.Structure
import com.sun.jna.platform.win32.WinDef.ULONG
import com.sun.jna.platform.win32.WinDef.USHORT
import wg.core.sock.SockAddrIn4

class WireGuardPeer : Structure() {
    @JvmField
    var Flags: ULONG = ULONG(0)

    @JvmField
    var Reserved: ULONG = ULONG(0)

    @JvmField
    var PublicKey: ByteArray = ByteArray(32)

    @JvmField
    var PresharedKey: ByteArray = ByteArray(32)

    @JvmField
    var PersistentKeepalive: USHORT = USHORT(0)

    @JvmField
    var Endpoint: SockAddrIn4 = SockAddrIn4()

    @JvmField
    var TxBytes: NativeLong = NativeLong(0L)

    @JvmField
    var RxBytes: NativeLong = NativeLong(0L)

    @JvmField
    var LastHandshake: NativeLong = NativeLong(0L)

    @JvmField
    var AllowedIPsCount: ULONG = ULONG(0)

    override fun getFieldOrder(): List<String> {
        return listOf(
            "Flags", "Reserved", "PublicKey", "PresharedKey", "PersistentKeepalive",
            "Endpoint", "TxBytes", "RxBytes", "LastHandshake", "AllowedIPsCount"
        )
    }
}
