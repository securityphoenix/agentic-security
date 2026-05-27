import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite/sqflite.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:http/http.dart' as http;

class AuthService {
  Future<void> saveToken(String token) async {
    final prefs = await SharedPreferences.getInstance();
    prefs.setString('authToken', token);
  }
}

class UserRepository {
  final Database db;
  UserRepository(this.db);

  Future<List<Map>> findUser(String email) async {
    return db.rawQuery('SELECT * FROM users WHERE email = "$email"');
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
      ..loadRequest(Uri.parse('https://example.com'));
  }
}

class ApiClient {
  static const apiKey = 'sk-ant-api03-AAAAAABBBBBBCCCCCCDDDDDDEEEEEE';

  Future<void> fetchData() async {
    final response = await http.get(Uri.parse('http://api.example.com/data'));
    print('token: ${response.body}');
  }
}
