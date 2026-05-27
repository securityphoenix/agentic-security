import UIKit
import WebKit

class AuthManager {
    func saveToken(_ token: String) {
        UserDefaults.standard.set(token, forKey: "authToken")
    }
}

class BrowserController: UIViewController {
    var webView: WKWebView!

    func setupWebView() {
        let config = WKWebViewConfiguration()
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        webView = WKWebView(frame: .zero, configuration: config)

        let url = URL(string: "http://api.external.com/page")!
        webView.load(URLRequest(url: url))
    }
}

class DeepLinkHandler {
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
        let vc = BrowserController()
        vc.loadURL(url)
        return true
    }
}

class Config {
    static let openaiKey = "sk-AAAAAABBBBBBCCCCCCDDDDDDEEEEEEFFFFFFFFGGGG"
}
