package wg

import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.ptr.PointerByReference
import wg.core.WireGuardAdapterLoggerLevel
import wg.core.WireGuardAdapterState
import wg.core.WireguardLibrary
import java.io.File
import kotlin.math.log


class WireGuardManager {

    private val instance = WireguardLibrary.INSTANCE
    companion object {
        private const val NAME = "WG Adapter"
        private const val TYPE = "WireGuard"
        private const val CUSTOM_ERROR = -100
        private var adapter: Pointer? = null
    }

    fun driverVersion() = instance.WireGuardGetRunningDriverVersion()

    fun addEnviromentalVariable() {
        val newEnv = listOf(
            "PATH" to WireguardLibrary.sysProperty
        )
        // Get the current PATH environment variable
        val currentPath = System.getenv("PATH")

        // Join new DLL paths with the existing PATH
        val newPath = newEnv.joinToString(File.pathSeparator, currentPath + File.pathSeparator)

        // Use ProcessBuilder to launch new processes with the updated environment
        val processBuilder = ProcessBuilder()
        val environment = processBuilder.environment()
        environment["PATH"] = newPath
    }

    fun openAdapter(onInvalid: () -> Unit) {
        val _adapter = instance.WireGuardOpenAdapter(NAME)

        if (Pointer.nativeValue(_adapter) != 0L)
            adapter = _adapter
        else
            onInvalid()
    }
    fun createAdapter(onFailed: ((String) -> Unit)? = null) {
        try {
            val adapterHandler = instance.WireGuardCreateAdapter(NAME, TYPE, null)

            if (adapterHandler != Pointer.NULL && Pointer.nativeValue(adapterHandler) != 0L) {
                adapter = adapterHandler
                return
            }
            else {
                val errorCode = Kernel32.INSTANCE.GetLastError()
                onFailed?.invoke("Failed to create adapter. Error code: $errorCode")
            }

        } catch (e: Exception) {
            onFailed?.invoke(e.message.toString())
        }
    }

    fun closeAdapter(onError: (String) -> Unit) = adapter?.let {
        instance.WireGuardCloseAdapter(it)
        adapter = null
    } ?: run {
        onError("Adapter Pointer is null, Open or Create Adapter before proceeding")
    }

    fun getAdapterState(onState: (Int) -> Unit) {
        val stateRef = PointerByReference()
        adapter?.let {
            if (instance.WireGuardGetAdapterState(adapter!!, stateRef)) {
                onState(stateRef.value.getInt(0))  // Assuming the state is represented by an integer
                return
            }

            onState(CUSTOM_ERROR)
        } ?: run {
            onState(CUSTOM_ERROR)
        }
    }

    fun setAdapterState(state: WireGuardAdapterState) {
        adapter?.let {
            instance.WireGuardSetAdapterState(adapter!!, state)
        } ?: kotlin.run {

        }
    }

    fun setAdapterLogging(loggingLevel: WireGuardAdapterLoggerLevel): Boolean {
        adapter?.let {
            return instance.WireGuardSetAdapterLogging(adapter!!, loggingLevel)
        }

        return false
    }
}