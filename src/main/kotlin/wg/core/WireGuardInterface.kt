package wg.core

import com.sun.jna.Structure
import com.sun.jna.platform.win32.WinDef.DWORD

class WireGuardInterface : Structure() {
    @JvmField
    var PrivateKey = ByteArray(32)

    @JvmField
    var PublicKey = ByteArray(32)

    @JvmField
    var PresharedKey = ByteArray(32)

    @JvmField
    var ListenPort = DWORD(0)

    @JvmField
    var Flags = DWORD(0)

    override fun getFieldOrder() = listOf(
        "PrivateKey",
        "PublicKey",
        "PresharedKey",
        "ListenPort",
        "Flags"
    )
}