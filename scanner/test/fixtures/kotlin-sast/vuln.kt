import java.util.concurrent.*
import org.yaml.snakeyaml.Yaml
import com.google.gson.Gson

fun handler(request: Map<String, Any?>) {
    val name = request["name"]!!                             // force-unwrap on user input
    Runtime.getRuntime().exec("echo " + request["cmd"])     // command injection
    val parsed = Yaml().load<Any>(request["yaml"] as String) // unsafe YAML
    val any = Gson().fromJson(request["json"] as String, Any::class.java)  // polymorphic
    val data = java.io.File(request["path"] as String).readText()         // path traversal
}

fun blockOnMain() {
    runBlocking {
        delay(1000)
    }
}
