package wg.helper

import com.sun.jna.Pointer

interface WireguardAdapterCreatorListener {
    fun onSuccess(pointer: Pointer)
    fun onFailed(message: String)
}