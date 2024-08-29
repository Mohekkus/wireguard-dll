package wg.core

import com.sun.jna.Pointer
import com.sun.jna.Structure

// Define the handle for the WireGuard adapter
typealias WIREGUARD_ADAPTER_HANDLE = Pointer

open class GUID: Structure() {
    @JvmField
    var Data1: Int = 0
    @JvmField
    var Data2: Short = 0
    @JvmField
    var Data3: Short = 0
    @JvmField
    var Data4 = ByteArray(8)

    class ByReference : GUID(), Structure.ByReference
    class ByValue : GUID(), Structure.ByValue
}