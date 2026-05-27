import { test } from 'node:test';
import { evaluateF1 } from './helpers/f1.js';

test('Dart/Flutter detector: vulnerable fixtures fire, clean fixtures are silent', async () => {
  await evaluateF1({
    name: 'dart-flutter',
    fixtureDir: 'dart-flutter',
    labels: [
      { file: 'vulnerable/app.dart', positive: true, matcher: /SharedPreferences.*secret/i },
      { file: 'vulnerable/app.dart', positive: true, matcher: /sql.*injection/i },
      { file: 'vulnerable/app.dart', positive: true, matcher: /WebView.*JavaScript.*unrestricted/i },
      { file: 'vulnerable/app.dart', positive: true, matcher: /Hardcoded.*Anthropic/i },
      { file: 'vulnerable/app.dart', positive: true, matcher: /Cleartext HTTP/i },
      { file: 'vulnerable/app.dart', positive: true, matcher: /print.*token|password/i },
      { file: 'clean/app.dart',      positive: false, matcher: /SharedPreferences.*secret/i },
      { file: 'clean/app.dart',      positive: false, matcher: /sql.*injection/i },
      { file: 'clean/app.dart',      positive: false, matcher: /WebView.*JavaScript.*unrestricted/i },
      { file: 'clean/app.dart',      positive: false, matcher: /Hardcoded/i },
      { file: 'clean/app.dart',      positive: false, matcher: /Cleartext HTTP/i },
    ],
    floors: { precision: 0.85, recall: 0.80, f1: 0.80 },
  });
});

test('Swift detector: vulnerable fixtures fire, clean fixtures are silent', async () => {
  await evaluateF1({
    name: 'swift',
    fixtureDir: 'swift',
    labels: [
      { file: 'vulnerable/App.swift', positive: true, matcher: /UserDefaults.*secret/i },
      { file: 'vulnerable/App.swift', positive: true, matcher: /WKWebView.*JavaScript.*no.*navigationDelegate/i },
      { file: 'vulnerable/App.swift', positive: true, matcher: /Cleartext HTTP/i },
      { file: 'vulnerable/App.swift', positive: true, matcher: /Hardcoded.*OpenAI/i },
      { file: 'vulnerable/App.swift', positive: true, matcher: /Deep.?link.*validate/i },
      { file: 'clean/App.swift',      positive: false, matcher: /UserDefaults.*secret/i },
      { file: 'clean/App.swift',      positive: false, matcher: /WKWebView.*JavaScript.*no.*navigationDelegate/i },
      { file: 'clean/App.swift',      positive: false, matcher: /Cleartext HTTP/i },
      { file: 'clean/App.swift',      positive: false, matcher: /Hardcoded/i },
      { file: 'clean/App.swift',      positive: false, matcher: /Deep.?link.*validate/i },
    ],
    floors: { precision: 0.85, recall: 0.80, f1: 0.80 },
  });
});
