import UIKit
import WebKit
import Security

class AuthManager {
    func saveToken(_ token: String) {
        let data = token.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "authToken",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
}

class BrowserController: UIViewController, WKNavigationDelegate {
    var webView: WKWebView!
    let allowedHosts = ["example.com", "cdn.example.com"]

    func setupWebView() {
        let config = WKWebViewConfiguration()
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = self

        guard let url = URL(string: "https://example.com/page") else { return }
        webView.load(URLRequest(url: url))
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let host = navigationAction.request.url?.host,
              allowedHosts.contains(host) else {
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }
}

class DeepLinkHandler {
    let allowedSchemes = ["myapp"]
    let allowedHosts = ["settings", "profile"]

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
        guard let scheme = url.scheme, allowedSchemes.contains(scheme),
              let host = url.host, allowedHosts.contains(host) else {
            return false
        }
        return true
    }
}

class Config {
    static var apiKey: String {
        ProcessInfo.processInfo.environment["API_KEY"] ?? ""
    }
}
