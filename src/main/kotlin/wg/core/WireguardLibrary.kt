package wg.core

import com.sun.jna.*
import com.sun.jna.platform.win32.Guid.GUID
import com.sun.jna.platform.win32.WTypes.LPWSTR
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.platform.win32.WinDef.*
import com.sun.jna.platform.win32.WinNT.HANDLE
import com.sun.jna.ptr.PointerByReference
import com.sun.jna.win32.StdCallLibrary

interface WireguardLibrary: StdCallLibrary {

    // Corresponds to createAdapter
    fun WireGuardCreateAdapter(
        name: String,
        tunnelType: String,
        requestedGUID: PointerByReference?
    ): Pointer

    // Corresponds to openAdapter
    fun WireGuardOpenAdapter(name: String): Pointer

    // Corresponds to freeAdapter
    fun WireGuardCloseAdapter(adapter: Pointer)

    // Corresponds to getAdapterLUID
    fun WireGuardGetAdapterLUID(adapter: Pointer, luid: PointerByReference)

    // Corresponds to getConfiguration
    fun WireGuardGetConfiguration(
        adapter: Pointer,
        iface: ByteArray,
        bytes: ULONG
    ): Boolean

    // Corresponds to setConfiguration
    fun WireGuardSetConfiguration(
        adapter: Pointer,
        wireGuardConfig: Pointer,
        bytes: ULONG
    ): Boolean


    // Equivalent of C#'s setAdapterState function
    @Suppress("FunctionName")
    fun WireGuardSetAdapterState(adapter: Pointer, wireGuardAdapterState: Int): Boolean

    // Equivalent of C#'s getAdapterState function
    fun WireGuardGetAdapterState(
        adapter: Pointer,
        wireGuardAdapterState: PointerByReference // Use PointerByReference for enum value
    ): Boolean

    // Equivalent of C#'s getRunningDriverVersion function
    fun WireGuardGetRunningDriverVersion(): Int

    // Equivalent of C#'s setAdapterLogging function
    fun WireGuardSetAdapterLogging(
        adapter: Pointer,
        loggingLevel: Int
    ): Boolean

    fun WireGuardSetLogger(callback: WireGuardLoggerCallback): Boolean

    companion object {
        val sysProperty = when (System.getProperty("os.arch")) {
            "amd64", "x86_64" -> "amd64"
            "x86" -> "x86"
            "arm" -> "arm"
            "aarch64" -> "arm64"
            else -> throw UnsupportedOperationException("Unsupported architecture")
        }

        val INSTANCE: WireguardLibrary = Native.load("wg/$sysProperty/wireguard", WireguardLibrary::class.java)

    }
}