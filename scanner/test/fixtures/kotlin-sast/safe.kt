import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

fun handler(request: Map<String, Any?>) {
    val name = request["name"] as? String ?: "anonymous"   // safe: no force unwrap
    val parsed = Yaml(SafeConstructor()).load<Any>(request["yaml"] as String)   // safe YAML
}
