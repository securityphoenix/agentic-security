// Tests for v5 framework + language coverage detectors.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { scanDjangoHardening } from '../src/sast/django-hardening.js';
import { scanDefiDeep } from '../src/sast/defi-deep.js';
import { scanSpringbootHardening } from '../src/sast/springboot-hardening.js';
import { scanLaravelHardening } from '../src/sast/laravel-hardening.js';
import { scanSwift } from '../src/sast/swift.js';
import { scanDartFlutter } from '../src/sast/dart-flutter.js';
import { scanLlmTradingAgent } from '../src/sast/llm-trading-agent.js';
import { scanMobileManifest } from '../src/sast/mobile-manifest.js';
import { scanQuarkusHardening } from '../src/sast/quarkus-hardening.js';
import { scanFastapiHardening } from '../src/sast/fastapi-hardening.js';

// ── Django ────────────────────────────────────────────────────────────────
test('django: DEBUG=True in production settings', () => {
  const text = `
INSTALLED_APPS = ['django.contrib.admin']
ROOT_URLCONF = 'app.urls'
DEBUG = True
ALLOWED_HOSTS = ['*']
`;
  const findings = scanDjangoHardening('settings/production.py', text);
  assert.ok(findings.some(f => /DEBUG=True/.test(f.vuln) && f.severity === 'critical'));
  assert.ok(findings.some(f => /ALLOWED_HOSTS/.test(f.vuln)));
});

test('django: hardcoded SECRET_KEY', () => {
  const text = `
INSTALLED_APPS = ['django.contrib.admin']
ROOT_URLCONF = 'app.urls'
SECRET_KEY = 'django-insecure-abc123def456ghi789jkl012'
`;
  const findings = scanDjangoHardening('settings/base.py', text);
  assert.ok(findings.some(f => /SECRET_KEY/.test(f.vuln) && f.severity === 'critical'));
});

test('django: @csrf_exempt without webhook signature check', () => {
  const text = `
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render

@csrf_exempt
def update_profile(request):
    return render(request, 'profile.html')
`;
  const findings = scanDjangoHardening('app/views.py', text);
  assert.ok(findings.some(f => /csrf_exempt/.test(f.vuln)));
});

test('django: ignores non-Django Python files', () => {
  const findings = scanDjangoHardening('src/utils.py', 'import os\nDEBUG = True\n');
  assert.equal(findings.length, 0);
});

// ── DeFi deep pack ────────────────────────────────────────────────────────
test('defi: donation/inflation attack on share math', () => {
  const sol = `
pragma solidity ^0.8.0;
contract Vault {
  uint256 public totalShares;
  IERC20 public token;
  function deposit(uint256 assets) external returns (uint256 shares) {
    shares = (assets * totalShares) / token.balanceOf(address(this));
    totalShares += shares;
  }
}`;
  const findings = scanDefiDeep('Vault.sol', sol);
  assert.ok(findings.some(f => /donation\/inflation/i.test(f.vuln)));
});

test('defi: swap without amountOutMin / deadline', () => {
  const sol = `
pragma solidity ^0.8.0;
contract Router {
  function swapTokens(uint256 amountIn) external returns (uint256 amountOut) {
    amountOut = _calc(amountIn);
  }
}`;
  const findings = scanDefiDeep('Router.sol', sol);
  assert.ok(findings.some(f => /amountOutMin/.test(f.vuln)));
  assert.ok(findings.some(f => /deadline/.test(f.vuln)));
});

test('defi: ownable single-step', () => {
  const sol = `
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";
contract Pool is Ownable {
  function setFee(uint256 fee) external onlyOwner {}
}`;
  const findings = scanDefiDeep('Pool.sol', sol);
  assert.ok(findings.some(f => /single-step Ownable/.test(f.vuln)));
});

// ── SpringBoot ────────────────────────────────────────────────────────────
test('springboot: literal spring.security.user.password in properties', () => {
  const text = 'spring.security.user.name=admin\nspring.security.user.password=hunter2\n';
  const findings = scanSpringbootHardening('src/main/resources/application.properties', text);
  assert.ok(findings.some(f => /literal/.test(f.vuln) && f.severity === 'critical'));
});

test('springboot: actuator endpoints exposed via wildcard', () => {
  const text = 'management.endpoints.web.exposure.include=*\n';
  const findings = scanSpringbootHardening('src/main/resources/application.properties', text);
  assert.ok(findings.some(f => /Actuator/.test(f.vuln)));
});

test('springboot: @CrossOrigin(origins="*")', () => {
  const java = `
package com.example;
import org.springframework.web.bind.annotation.*;
@RestController
@CrossOrigin(origins = "*")
public class ApiController {
  @PostMapping("/api/data")
  public void save() {}
}`;
  const findings = scanSpringbootHardening('src/main/java/com/example/ApiController.java', java);
  assert.ok(findings.some(f => /CrossOrigin/.test(f.vuln)));
});

test('springboot: JWT.decode without verify', () => {
  const java = `
package com.example;
import org.springframework.stereotype.Service;
import com.auth0.jwt.JWT;
@Service
public class AuthService {
  public String parse(String token) { return JWT.decode(token).getSubject(); }
}`;
  const findings = scanSpringbootHardening('src/main/java/com/example/AuthService.java', java);
  assert.ok(findings.some(f => /JWT\.decode/.test(f.vuln) && f.severity === 'critical'));
});

// ── Laravel ──────────────────────────────────────────────────────────────
test('laravel: APP_DEBUG=true and APP_KEY= empty', () => {
  const text = 'APP_DEBUG=true\nAPP_KEY=\nDB_HOST=localhost\n';
  const findings = scanLaravelHardening('.env', text);
  assert.ok(findings.some(f => /APP_DEBUG/.test(f.vuln)));
  assert.ok(findings.some(f => /APP_KEY is empty/.test(f.vuln)));
});

test('laravel: dd() in controller', () => {
  const php = `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class HomeController extends \\Illuminate\\Routing\\Controller {
  public function index(Request $request) {
    dd($request->all());
  }
}`;
  const findings = scanLaravelHardening('app/Http/Controllers/HomeController.php', php);
  assert.ok(findings.some(f => /dd\(\)/.test(f.vuln)));
});

test('laravel: Eloquent model without $fillable/$guarded', () => {
  const php = `<?php
namespace App\\Models;
use Illuminate\\Database\\Eloquent\\Model;
class User extends Model {
  protected $table = 'users';
}`;
  const findings = scanLaravelHardening('app/Models/User.php', php);
  assert.ok(findings.some(f => /mass assignment/i.test(f.vuln)));
});

// ── Swift ────────────────────────────────────────────────────────────────
test('swift: UserDefaults for token storage', () => {
  const code = `
import Foundation
func saveToken(token: String) {
  UserDefaults.standard.set(token, forKey: "authToken")
}`;
  const findings = scanSwift('Source/Auth.swift', code);
  assert.ok(findings.some(f => /UserDefaults/.test(f.vuln)));
});

test('swift: URL force-unwrap', () => {
  const code = `let url = URL(string: deepLinkInput)!`;
  const findings = scanSwift('Source/Open.swift', code);
  assert.ok(findings.some(f => /force-unwrap/.test(f.vuln)));
});

test('swift: hardcoded Anthropic key', () => {
  const code = `let apiKey = "sk-ant-abcdefghij1234567890abcdefghij"`;
  const findings = scanSwift('Source/Config.swift', code);
  assert.ok(findings.some(f => /Hardcoded/.test(f.vuln)));
});

// ── Dart / Flutter ───────────────────────────────────────────────────────
test('dart: SharedPreferences for token', () => {
  const code = `
import 'package:shared_preferences/shared_preferences.dart';
Future<void> saveToken(String token) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('authToken', token);
}`;
  const findings = scanDartFlutter('lib/auth.dart', code);
  assert.ok(findings.some(f => /SharedPreferences/.test(f.vuln)));
});

test('dart: rawQuery with interpolation', () => {
  const code = `
import 'package:sqflite/sqflite.dart';
Future<void> q(Database db, String email) async {
  await db.rawQuery("SELECT * FROM users WHERE email = '\$email'");
}`;
  const findings = scanDartFlutter('lib/db.dart', code);
  assert.ok(findings.some(f => /SQL injection/i.test(f.vuln)));
});

// ── LLM trading agent ────────────────────────────────────────────────────
test('llm-trading: no simulation before send_raw_transaction', () => {
  const py = `
from web3 import Web3
import anthropic
def trade(w3, signed):
    return w3.eth.send_raw_transaction(signed.raw_transaction)
`;
  const findings = scanLlmTradingAgent('agent/trader.py', py);
  assert.ok(findings.some(f => /no.*simulation|prior simulation/i.test(f.vuln)));
});

test('llm-trading: hardcoded 64-hex private key', () => {
  const py = `
from web3 import Web3
import anthropic
PRIVATE_KEY = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
def trade(): pass
`;
  const findings = scanLlmTradingAgent('agent/wallet.py', py);
  assert.ok(findings.some(f => /Hardcoded.*private key/i.test(f.vuln) && f.severity === 'critical'));
});

// ── Mobile manifest ──────────────────────────────────────────────────────
test('mobile-manifest: AndroidManifest exported=true on non-launcher activity', () => {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<manifest>
  <application android:debuggable="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><category android:name="android.intent.category.LAUNCHER" /></intent-filter>
    </activity>
    <activity android:name=".SecretActivity" android:exported="true">
      <intent-filter><action android:name="myapp.OPEN" /></intent-filter>
    </activity>
  </application>
</manifest>`;
  const findings = scanMobileManifest('android/app/src/main/AndroidManifest.xml', xml);
  // Launcher activity is NOT flagged; SecretActivity IS flagged.
  assert.ok(findings.some(f => /exported="true"/.test(f.vuln) && !/MainActivity/.test(f.vuln)));
  // Plus debuggable=true.
  assert.ok(findings.some(f => /debuggable="true"/.test(f.vuln) && f.severity === 'critical'));
});

test('mobile-manifest: Info.plist ATS disabled', () => {
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
  </dict>
</dict></plist>`;
  const findings = scanMobileManifest('ios/Runner/Info.plist', plist);
  assert.ok(findings.some(f => /ATS|NSAllowsArbitraryLoads/i.test(f.vuln)));
});

// ── Quarkus ──────────────────────────────────────────────────────────────
test('quarkus: oidc.credentials.secret literal in properties', () => {
  const text = 'quarkus.oidc.auth-server-url=https://auth.example.com\nquarkus.oidc.credentials.secret=hardcodedSecret123\n';
  const findings = scanQuarkusHardening('src/main/resources/application.properties', text);
  assert.ok(findings.some(f => /OIDC.*plaintext/i.test(f.vuln) && f.severity === 'critical'));
});

// ── FastAPI ──────────────────────────────────────────────────────────────
test('fastapi: CORS wildcard + credentials', () => {
  const py = `
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
`;
  const findings = scanFastapiHardening('app/main.py', py);
  assert.ok(findings.some(f => /CORS.*credentials/i.test(f.vuln) && f.severity === 'critical'));
});

test('fastapi: jwt.decode with verify_signature=False', () => {
  const py = `
from fastapi import FastAPI
import jwt
app = FastAPI()
def parse(token):
    return jwt.decode(token, options={"verify_signature": False})
`;
  const findings = scanFastapiHardening('app/auth.py', py);
  assert.ok(findings.some(f => /verify_signature=False/i.test(f.vuln) && f.severity === 'critical'));
});

test('fastapi: mutating endpoint without Depends auth', () => {
  const py = `
from fastapi import FastAPI
app = FastAPI()
@app.post("/users")
def create_user(name: str):
    return {"name": name}
`;
  const findings = scanFastapiHardening('app/main.py', py);
  assert.ok(findings.some(f => /no Security\(\) \/ Depends\(\)/i.test(f.vuln)));
});
