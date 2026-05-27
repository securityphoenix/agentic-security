import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:sqflite/sqflite.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:http/http.dart' as http;

class AuthService {
  final _storage = FlutterSecureStorage();

  Future<void> saveToken(String token) async {
    await _storage.write(key: 'authToken', value: token);
  }
}

class UserRepository {
  final Database db;
  UserRepository(this.db);

  Future<List<Map>> findUser(String email) async {
    return db.query('users', where: 'email = ?', whereArgs: [email]);
  }
}

class BrowserPage extends StatefulWidget {
  @override
  _BrowserPageState createState() => _BrowserPageState();
}

class _BrowserPageState extends State<BrowserPage> {
  late WebViewController controller;

  void initWebView() {
    controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setNavigationDelegate(NavigationDelegate(
        onNavigationRequest: (request) {
          if (!request.url.startsWith('https://example.com')) {
            return NavigationDecision.prevent;
          }
          return NavigationDecision.navigate;
        },
      ))
      ..loadRequest(Uri.parse('https://example.com'));
  }
}

class ApiClient {
  final String apiKey;
  ApiClient(this.apiKey);

  Future<void> fetchData() async {
    final response = await http.get(
      Uri.parse('https://api.example.com/data'),
      headers: {'Authorization': 'Bearer $apiKey'},
    ).timeout(Duration(seconds: 30));
  }
}
