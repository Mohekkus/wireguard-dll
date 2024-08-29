import androidx.compose.desktop.ui.tooling.preview.Preview
import androidx.compose.material.Button
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import kotlinx.coroutines.*
import wg.WireGuardManager
import wg.WireguardImplementation
import wg.core.IoctlInterfaceFlags
import wg.core.SOCKADDR_INET
import wg.core.WireGuardInterface
import java.net.InetAddress

@Composable
@Preview
fun App() {
    var text by remember { mutableStateOf("Hello, World!") }

    MaterialTheme {
        Button(onClick = {
            text = "Hello, Desktop!"
        }) {
            Text(text)
        }
    }
}


val gateway = VPNGateway.INSTANCE
suspend fun main() {
    gateway.test()
}

class VPNGateway: WireGuardInterface {

    companion object {
        val INSTANCE = VPNGateway()
    }

    private val implementation = WireguardImplementation(this)

    suspend fun test() {
        implementation.connectConfig(
            ilistenPort = 1024,
            iprivateKey = "6Dcn9c2QIvpxMOUyEFcsqkEQHPMs0hYzRtOcgKkOaHQ=".toByteArray(),
            ppublicKey = "MKxF3963hjD/MLGSIcGRLaco/N5uDN/Dslt/k675Knc=".toByteArray(),
            pendpoint = "indo7.vpnjantit.com:1024"
        )
        delay(20000)
        disconnect()
    }

    fun disconnect() = implementation.disconnect()

    override fun onError(message: String) {
        println("Error ---> $message")
    }

    override fun onMessage(message: String) {
        println("Message ---> $message")
    }
}
