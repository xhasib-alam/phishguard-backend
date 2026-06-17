import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:open_filex/open_filex.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  runApp(const PhishGuardApp());
}

class PhishGuardApp extends StatelessWidget {
  const PhishGuardApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'PhishGuard',
      debugShowCheckedModeBanner: false,
      themeMode: ThemeMode.dark,
      darkTheme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF05070D),
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF22D3EE),
          brightness: Brightness.dark,
          primary: const Color(0xFF22D3EE),
          secondary: const Color(0xFF22C55E),
          error: const Color(0xFFEF4444),
        ),
        cardTheme: CardThemeData(
          color: const Color(0xFF0B1220),
          elevation: 0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(18),
            side: const BorderSide(color: Color(0x2638BDF8)),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: const Color(0xFF07111F),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(14),
            borderSide: const BorderSide(color: Color(0x2638BDF8)),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(14),
            borderSide: const BorderSide(color: Color(0x2638BDF8)),
          ),
        ),
      ),
      home: const BootstrapScreen(),
    );
  }
}

class BootstrapScreen extends StatefulWidget {
  const BootstrapScreen({super.key});

  @override
  State<BootstrapScreen> createState() => _BootstrapScreenState();
}

class _BootstrapScreenState extends State<BootstrapScreen> {
  late Future<AppConfig> _future;

  @override
  void initState() {
    super.initState();
    _future = AppConfig.load();
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<AppConfig>(
      future: _future,
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Scaffold(body: Center(child: CircularProgressIndicator()));
        }
        return HomeShell(config: snapshot.data!);
      },
    );
  }
}

class AppConfig {
  AppConfig({required this.baseUrl, required this.token});

  String baseUrl;
  String token;

  static const defaultBaseUrl = 'http://10.0.2.2:5000';

  static Future<AppConfig> load() async {
    final prefs = await SharedPreferences.getInstance();
    return AppConfig(
      baseUrl: prefs.getString('baseUrl') ?? defaultBaseUrl,
      token: prefs.getString('token') ?? '',
    );
  }

  Future<void> save() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('baseUrl', baseUrl);
    await prefs.setString('token', token);
  }

  Future<void> clearToken() async {
    token = '';
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('token');
  }
}

class ApiClient {
  ApiClient(this.config);

  final AppConfig config;

  Uri uri(String path) => Uri.parse('${config.baseUrl}$path');

  Map<String, String> get headers {
    return {
      'Content-Type': 'application/json',
      if (config.token.isNotEmpty) 'Authorization': 'Bearer ${config.token}',
    };
  }

  Future<Map<String, dynamic>> getJson(String path) async {
    final response = await http.get(uri(path), headers: headers);
    return _decode(response);
  }

  Future<Map<String, dynamic>> postJson(String path, Map<String, dynamic> body) async {
    final response = await http.post(uri(path), headers: headers, body: jsonEncode(body));
    return _decode(response);
  }

  Future<http.Response> postRaw(String path, Map<String, dynamic> body) {
    return http.post(uri(path), headers: headers, body: jsonEncode(body));
  }

  Map<String, dynamic> _decode(http.Response response) {
    final data = jsonDecode(response.body) as Map<String, dynamic>;
    if (response.statusCode >= 400 || data['success'] == false) {
      throw ApiException(data['error']?.toString() ?? data['message']?.toString() ?? 'Request failed');
    }
    return data;
  }
}

class ApiException implements Exception {
  ApiException(this.message);
  final String message;

  @override
  String toString() => message;
}

class HomeShell extends StatefulWidget {
  const HomeShell({super.key, required this.config});

  final AppConfig config;

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _index = 0;

  late final ApiClient api = ApiClient(widget.config);

  @override
  Widget build(BuildContext context) {
    final screens = [
      ScanScreen(api: api),
      HistoryScreen(api: api),
      EmailScreen(api: api),
      SettingsScreen(config: widget.config, onChanged: () => setState(() {})),
    ];

    return Scaffold(
      appBar: AppBar(
        title: const Text('PhishGuard'),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: Center(
              child: Text(
                widget.config.token.isEmpty ? 'Guest' : 'Authenticated',
                style: TextStyle(color: Theme.of(context).colorScheme.primary),
              ),
            ),
          ),
        ],
      ),
      body: screens[_index],
      bottomNavigationBar: NavigationBar(
        selectedIndex: _index,
        onDestinationSelected: (value) => setState(() => _index = value),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.security), label: 'Scan'),
          NavigationDestination(icon: Icon(Icons.history), label: 'History'),
          NavigationDestination(icon: Icon(Icons.mail_lock), label: 'Email'),
          NavigationDestination(icon: Icon(Icons.settings), label: 'Settings'),
        ],
      ),
    );
  }
}

class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key, required this.api});

  final ApiClient api;

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  final _url = TextEditingController(text: 'https://google.com@secure-login-google.com/verify/account');
  Map<String, dynamic>? _result;
  bool _loading = false;

  @override
  void dispose() {
    _url.dispose();
    super.dispose();
  }

  Future<void> _scan() async {
    if (_url.text.trim().isEmpty) return;
    setState(() => _loading = true);
    try {
      final response = await widget.api.postJson('/api/v1/scan', {'url': _url.text.trim()});
      setState(() => _result = response['data'] as Map<String, dynamic>);
    } catch (error) {
      _showError(error.toString());
    } finally {
      setState(() => _loading = false);
    }
  }

  Future<void> _downloadReport() async {
    if (_result == null) return;
    try {
      final details = (_result!['details'] as Map?) ?? {};
      final url = details['url']?.toString() ?? _url.text.trim();
      final response = await widget.api.postRaw('/api/v1/reports/pdf', {'url': url});
      if (response.statusCode >= 400) {
        throw ApiException('Could not generate PDF report');
      }
      final directory = await getTemporaryDirectory();
      final domain = (_result!['domain'] ?? 'report').toString().replaceAll(RegExp(r'[^a-zA-Z0-9.-]'), '-');
      final file = File('${directory.path}/phishguard-$domain.pdf');
      await file.writeAsBytes(response.bodyBytes);
      if (!mounted) return;
      await showModalBottomSheet<void>(
        context: context,
        builder: (context) => SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                ListTile(
                  leading: const Icon(Icons.picture_as_pdf),
                  title: const Text('Open PDF report'),
                  onTap: () {
                    Navigator.pop(context);
                    OpenFilex.open(file.path);
                  },
                ),
                ListTile(
                  leading: const Icon(Icons.share),
                  title: const Text('Share PDF report'),
                  onTap: () {
                    Navigator.pop(context);
                    Share.shareXFiles([XFile(file.path)], text: 'PhishGuard threat report');
                  },
                ),
              ],
            ),
          ),
        ),
      );
    } catch (error) {
      _showError(error.toString());
    }
  }

  void _showError(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    return RefreshIndicator(
      onRefresh: _scan,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const HeroPanel(),
          const SizedBox(height: 16),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text('URL Scanner', style: Theme.of(context).textTheme.titleLarge),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _url,
                    keyboardType: TextInputType.url,
                    decoration: const InputDecoration(
                      labelText: 'Target URL',
                      prefixIcon: Icon(Icons.link),
                    ),
                  ),
                  const SizedBox(height: 12),
                  FilledButton.icon(
                    onPressed: _loading ? null : _scan,
                    icon: _loading
                        ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Icon(Icons.radar),
                    label: Text(_loading ? 'Scanning...' : 'Scan URL'),
                  ),
                ],
              ),
            ),
          ),
          if (_result != null) ...[
            const SizedBox(height: 16),
            ResultCard(result: _result!, onDownloadReport: _downloadReport),
          ],
        ],
      ),
    );
  }
}

class HeroPanel extends StatelessWidget {
  const HeroPanel({super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(24),
        gradient: const LinearGradient(
          colors: [Color(0xFF07111F), Color(0xFF052E34)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        border: Border.all(color: const Color(0x3338BDF8)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Cyber Threat Intelligence',
            style: TextStyle(
              color: Theme.of(context).colorScheme.primary,
              fontWeight: FontWeight.w800,
              letterSpacing: 1.1,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'AI-based phishing detection for URLs, emails, reports, and mobile workflows.',
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900),
          ),
        ],
      ),
    );
  }
}

class ResultCard extends StatelessWidget {
  const ResultCard({super.key, required this.result, required this.onDownloadReport});

  final Map<String, dynamic> result;
  final VoidCallback onDownloadReport;

  @override
  Widget build(BuildContext context) {
    final status = (result['status'] ?? result['verdict'] ?? 'safe').toString();
    final riskScore = result['risk_score'] ?? 0;
    final confidence = result['confidence'] ?? 0;
    final reasons = (result['reasons'] as List?)?.map((e) => e.toString()).toList() ?? const <String>[];
    final recommendations =
        (result['recommendations'] as List?)?.map((e) => e.toString()).toList() ?? const <String>[];
    final color = switch (status) {
      'phishing' => const Color(0xFFEF4444),
      'suspicious' => const Color(0xFFF59E0B),
      _ => const Color(0xFF22C55E),
    };

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Chip(
                        label: Text(status.toUpperCase()),
                        backgroundColor: color.withOpacity(0.15),
                        side: BorderSide(color: color.withOpacity(0.4)),
                      ),
                      Text(result['domain']?.toString() ?? '-', style: Theme.of(context).textTheme.titleLarge),
                    ],
                  ),
                ),
                CircleAvatar(
                  radius: 36,
                  backgroundColor: color.withOpacity(0.16),
                  child: Text('$confidence%', style: TextStyle(color: color, fontWeight: FontWeight.w900)),
                ),
              ],
            ),
            const SizedBox(height: 16),
            LinearProgressIndicator(
              value: (riskScore is num ? riskScore : 0) / 100,
              minHeight: 10,
              color: color,
              backgroundColor: Colors.white10,
              borderRadius: BorderRadius.circular(99),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                InfoPill(label: 'Risk', value: '$riskScore/100'),
                InfoPill(label: 'Level', value: result['risk_level']?.toString() ?? '-'),
                InfoPill(label: 'Source', value: result['source']?.toString() ?? '-'),
              ],
            ),
            const SizedBox(height: 16),
            Text('Findings', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            ...reasons.map((item) => BulletText(item)),
            const SizedBox(height: 12),
            Text('Recommendations', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            ...recommendations.map((item) => BulletText(item)),
            const SizedBox(height: 16),
            OutlinedButton.icon(
              onPressed: onDownloadReport,
              icon: const Icon(Icons.picture_as_pdf),
              label: const Text('Download / Share PDF Report'),
            ),
          ],
        ),
      ),
    );
  }
}

class InfoPill extends StatelessWidget {
  const InfoPill({super.key, required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.06),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: Colors.white12),
      ),
      child: Text('$label: $value'),
    );
  }
}

class BulletText extends StatelessWidget {
  const BulletText(this.text, {super.key});

  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 7),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('• ', style: TextStyle(color: Theme.of(context).colorScheme.primary)),
          Expanded(child: Text(text)),
        ],
      ),
    );
  }
}

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key, required this.api});

  final ApiClient api;

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  final _search = TextEditingController();
  List<dynamic> _items = [];
  Map<String, dynamic> _analytics = {};
  bool _loading = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final history = await widget.api.getJson('/api/v1/history${_search.text.isEmpty ? '' : '?q=${Uri.encodeComponent(_search.text)}'}');
      final analytics = await widget.api.getJson('/api/v1/history/analytics');
      setState(() {
        _items = history['data'] as List<dynamic>;
        _analytics = analytics['data'] as Map<String, dynamic>;
      });
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(error.toString())));
      }
    } finally {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          TextField(
            controller: _search,
            decoration: InputDecoration(
              labelText: 'Search history',
              prefixIcon: const Icon(Icons.search),
              suffixIcon: IconButton(onPressed: _load, icon: const Icon(Icons.arrow_forward)),
            ),
            onSubmitted: (_) => _load(),
          ),
          const SizedBox(height: 12),
          AnalyticsGrid(data: _analytics),
          const SizedBox(height: 12),
          if (_loading) const Center(child: CircularProgressIndicator()),
          ..._items.map((item) => HistoryTile(item: item as Map<String, dynamic>)),
        ],
      ),
    );
  }
}

class AnalyticsGrid extends StatelessWidget {
  const AnalyticsGrid({super.key, required this.data});

  final Map<String, dynamic> data;

  @override
  Widget build(BuildContext context) {
    return GridView.count(
      crossAxisCount: 2,
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      childAspectRatio: 2.4,
      children: [
        StatCard(label: 'Total', value: data['total_scans']?.toString() ?? '0'),
        StatCard(label: 'Safe', value: data['safe']?.toString() ?? '0'),
        StatCard(label: 'Suspicious', value: data['suspicious']?.toString() ?? '0'),
        StatCard(label: 'Phishing', value: data['phishing']?.toString() ?? '0'),
      ],
    );
  }
}

class StatCard extends StatelessWidget {
  const StatCard({super.key, required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(label, style: TextStyle(color: Colors.white.withOpacity(0.68))),
            Text(value, style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900)),
          ],
        ),
      ),
    );
  }
}

class HistoryTile extends StatelessWidget {
  const HistoryTile({super.key, required this.item});

  final Map<String, dynamic> item;

  @override
  Widget build(BuildContext context) {
    final verdict = item['verdict']?.toString() ?? '-';
    return Card(
      child: ListTile(
        leading: Icon(
          verdict == 'phishing' ? Icons.warning_amber : Icons.check_circle,
          color: verdict == 'phishing' ? const Color(0xFFEF4444) : const Color(0xFF22C55E),
        ),
        title: Text(item['domain']?.toString() ?? '-'),
        subtitle: Text(item['url']?.toString() ?? ''),
        trailing: Text('${item['risk_score']}/100'),
      ),
    );
  }
}

class EmailScreen extends StatefulWidget {
  const EmailScreen({super.key, required this.api});

  final ApiClient api;

  @override
  State<EmailScreen> createState() => _EmailScreenState();
}

class _EmailScreenState extends State<EmailScreen> {
  final _content = TextEditingController(
    text: 'URGENT: Verify your password now at https://secure-login.example.com/account',
  );
  Map<String, dynamic>? _result;
  bool _loading = false;

  @override
  void dispose() {
    _content.dispose();
    super.dispose();
  }

  Future<void> _analyze() async {
    setState(() => _loading = true);
    try {
      final response = await widget.api.postJson('/api/v1/email/analyze', {'content': _content.text});
      setState(() => _result = response['data'] as Map<String, dynamic>);
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(error.toString())));
      }
    } finally {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final findings = (_result?['findings'] as List?)?.map((e) => e.toString()).toList() ?? const <String>[];
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text('Email Phishing Analyzer', style: Theme.of(context).textTheme.titleLarge),
                const SizedBox(height: 12),
                TextField(
                  controller: _content,
                  minLines: 8,
                  maxLines: 14,
                  decoration: const InputDecoration(labelText: 'Email content'),
                ),
                const SizedBox(height: 12),
                FilledButton.icon(
                  onPressed: _loading ? null : _analyze,
                  icon: const Icon(Icons.mail_lock),
                  label: Text(_loading ? 'Analyzing...' : 'Analyze Email'),
                ),
              ],
            ),
          ),
        ),
        if (_result != null) ...[
          const SizedBox(height: 16),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('${_result!['verdict'].toString().toUpperCase()} - ${_result!['risk_score']}/100',
                      style: Theme.of(context).textTheme.titleLarge),
                  const SizedBox(height: 12),
                  ...findings.map((item) => BulletText(item)),
                ],
              ),
            ),
          ),
        ],
      ],
    );
  }
}

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, required this.config, required this.onChanged});

  final AppConfig config;
  final VoidCallback onChanged;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late final TextEditingController _baseUrl = TextEditingController(text: widget.config.baseUrl);
  final _name = TextEditingController(text: 'PhishGuard User');
  final _email = TextEditingController();
  final _password = TextEditingController();
  bool _loading = false;

  @override
  void dispose() {
    _baseUrl.dispose();
    _name.dispose();
    _email.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _saveBaseUrl() async {
    widget.config.baseUrl = _baseUrl.text.trim().replaceAll(RegExp(r'/$'), '');
    await widget.config.save();
    widget.onChanged();
    _toast('API URL saved');
  }

  Future<void> _auth(String mode) async {
    setState(() => _loading = true);
    try {
      final api = ApiClient(widget.config);
      final response = await api.postJson('/api/v1/auth/$mode', {
        'name': _name.text.trim(),
        'email': _email.text.trim(),
        'password': _password.text,
      });
      widget.config.token = response['data']['token'].toString();
      await widget.config.save();
      widget.onChanged();
      _toast(mode == 'login' ? 'Logged in' : 'Registered');
    } catch (error) {
      _toast(error.toString());
    } finally {
      setState(() => _loading = false);
    }
  }

  Future<void> _logout() async {
    widget.config.token = '';
    await widget.config.clearToken();
    widget.onChanged();
    _toast('Logged out');
  }

  void _toast(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text('Backend API', style: Theme.of(context).textTheme.titleLarge),
                const SizedBox(height: 12),
                TextField(
                  controller: _baseUrl,
                  decoration: const InputDecoration(labelText: 'Base URL'),
                ),
                const SizedBox(height: 12),
                FilledButton.icon(
                  onPressed: _saveBaseUrl,
                  icon: const Icon(Icons.save),
                  label: const Text('Save API URL'),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text('Account', style: Theme.of(context).textTheme.titleLarge),
                const SizedBox(height: 12),
                TextField(controller: _name, decoration: const InputDecoration(labelText: 'Name')),
                const SizedBox(height: 10),
                TextField(controller: _email, decoration: const InputDecoration(labelText: 'Email')),
                const SizedBox(height: 10),
                TextField(
                  controller: _password,
                  obscureText: true,
                  decoration: const InputDecoration(labelText: 'Password'),
                ),
                const SizedBox(height: 12),
                FilledButton(
                  onPressed: _loading ? null : () => _auth('login'),
                  child: const Text('Login'),
                ),
                OutlinedButton(
                  onPressed: _loading ? null : () => _auth('register'),
                  child: const Text('Register'),
                ),
                TextButton.icon(
                  onPressed: _logout,
                  icon: const Icon(Icons.logout),
                  label: const Text('Logout'),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}
