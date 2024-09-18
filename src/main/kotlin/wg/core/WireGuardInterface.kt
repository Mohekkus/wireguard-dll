package wg.core

interface WireGuardInterface {
    fun onError(message: String)
    fun onMessage(message: String)
    fun onConfiguration(parseConfiguration: String)
}