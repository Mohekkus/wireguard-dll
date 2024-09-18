import androidx.compose.desktop.ui.tooling.preview.Preview
import androidx.compose.material.Button
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import com.sun.jna.Native
import com.sun.jna.platform.win32.Winsvc.SC_MANAGER_CREATE_SERVICE
import kotlinx.coroutines.*
import native.service.Advapi32
import native.service.Advapi32Implementation
import native.service.SERVICE_ALL_ACCESS
import wg.WireguardImplementation
import wg.core.IoctlInterfaceFlags
import wg.core.IoctlPeerFlags
import wg.core.WireGuardInterface
import java.util.*

@Composable
@Preview
fun App() {
    var text by remember { mutableStateOf("Hello, World!") }
    var isDisable by remember { mutableStateOf(false) }
    val gateway = VPNGateway {
        text += "\n$it"
        if (it.contains("-100"))
            isDisable = true
    }

    if (isDisable)
        CoroutineScope(Dispatchers.IO).launch {
            isDisable = false
            gateway.test()
        }


    MaterialTheme {
        Text(text)
        Button(
            onClick = {
                gateway.getState()
            }
        ) {
            Text("FUCKK")
        }
    }
}

fun main() = application {
    Window(
        onCloseRequest = ::exitApplication
    ) {
        App()
    }
}

class VPNGateway(private val addLog: (String) -> Unit): WireGuardInterface {

    private val implementation = WireguardImplementation(this)

    suspend fun test() {
        addLog("Starting")
        // WireGuard config values
        val privateKeyBase64 = "qLTEkVofFf6LFI6KtBxCfAQyaeFNkfHKBTqgAjBIUFY="
        val peerPublicKeyBase64 = "MKxF3963hjD/MLGSIcGRLaco/N5uDN/Dslt/k675Knc="
        val endpoint = "indo7.vpnjantit.com:1024"
        val listenPort: Short = 1024 // Define your listen port
        val dnsServers = listOf("1.1.1.1", "8.8.8.8") // DNS servers from the config

        // Convert Base64 to ByteArray
        val privateKey: ByteArray = Base64.getDecoder().decode(privateKeyBase64)
        val peerPublicKey: ByteArray = Base64.getDecoder().decode(peerPublicKeyBase64)

        implementation.// Call the connectConfig function
        connectConfig(
            iflags = IoctlInterfaceFlags.HAS_PRIVATE_KEY,  // Interface flag
            ilistenPort = listenPort,                      // Listen port
            iprivateKey = privateKey,                      // Private key for the interface
            ipublicKey = null,                             // Public key for the interface (optional)
            ipeerCount = 1,                                // One peer in the config
            pflags = IoctlPeerFlags.HAS_ENDPOINT,          // Peer flags
            ppublicKey = peerPublicKey,                    // Public key of the peer
            ppreshared = null,                             // No preshared key
            ppersistent = 45,                              // Persistence time (can be configured)
            pendpoint = endpoint, // Peer endpoint
            dns = dnsServers
        )
        delay(10000)
        disconnect()
    }

    fun disconnect() = implementation.disconnect()

    fun getState() = implementation.getState()

    override fun onError(message: String) {
        addLog("[Error] $message")
    }

    override fun onMessage(message: String) {
        addLog("[Message] $message")
    }

    override fun onConfiguration(parseConfiguration: String) {
        addLog("[Configuration] $parseConfiguration")
    }
}
