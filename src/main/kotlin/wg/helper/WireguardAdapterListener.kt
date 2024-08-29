package wg.helper

import com.sun.jna.Pointer

interface WireguardAdapterListener {

    fun onCreate(pointer: Pointer)
    fun onOpened()
    fun onClosed()
    fun onDelete()
}