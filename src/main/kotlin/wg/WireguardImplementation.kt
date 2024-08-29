package wg

class WireguardImplementation {

    private val manager = WireGuardManager()

    fun connectConfig() {

    }

    fun setConfig() {
    }

    fun connect() {
        manager.apply {

        }
    }

    fun disconnect() {
        manager.closeAdapter {

        }
    }

    fun version() = manager.driverVersion()
}