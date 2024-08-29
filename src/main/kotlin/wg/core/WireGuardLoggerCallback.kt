package wg.core

import com.sun.jna.Callback
import com.sun.jna.FromNativeContext
import com.sun.jna.ToNativeContext
import com.sun.jna.platform.win32.WTypes.LPWSTR
import com.sun.jna.platform.win32.WinDef.DWORD

interface WireGuardLoggerCallback: Callback {
    fun invoke(
        level: UInt,
        timestamp: DWORD,
        message: LPWSTR
    )
}
