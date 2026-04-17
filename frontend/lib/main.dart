import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

void main() {
  runApp(const MyApp());
}

class Alert {
  final DateTime timestamp;
  final String event;
  final String severity;
  final String message;
  final String filePath;

  Alert({
    required this.timestamp,
    required this.event,
    required this.severity,
    required this.message,
    required this.filePath,
  });

  factory Alert.fromJson(Map<String, dynamic> json) {
    return Alert(
      timestamp: DateTime.parse(json['timestamp']),
      event: json['event'] ?? 'UNKNOWN',
      severity: json['severity'] ?? 'low',
      message: json['message'] ?? '',
      filePath: json['file_path'] ?? '',
    );
  }
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'IDS Security Monitor',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.redAccent,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: const AlertDashboard(),
    );
  }
}

class AlertDashboard extends StatefulWidget {
  const AlertDashboard({super.key});

  @override
  State<AlertDashboard> createState() => _AlertDashboardState();
}

class _AlertDashboardState extends State<AlertDashboard> {
  final List<Alert> _alerts = [];
  ServerSocket? _tcpServer;
  RawDatagramSocket? _udpSocket;
  bool _isListening = false;

  @override
  void initState() {
    super.initState();
    _startListening();
  }

  Future<void> _startListening() async {
    try {
      // 1. TCP Listener
      _tcpServer = await ServerSocket.bind(InternetAddress.anyIPv4, 5005);
      _tcpServer?.listen((Socket client) {
        client.listen((List<int> data) {
          _processMessage(utf8.decode(data));
        }, onDone: () => client.close());
      });

      // 2. UDP Listener (Since you mentioned ncat -lu)
      _udpSocket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 5005);
      _udpSocket?.listen((RawSocketEvent event) {
        if (event == RawSocketEvent.read) {
          Datagram? dg = _udpSocket?.receive();
          if (dg != null) {
            _processMessage(utf8.decode(dg.data));
          }
        }
      });

      setState(() => _isListening = true);
      debugPrint('Listening on TCP/UDP 5005');
    } catch (e) {
      debugPrint('Error starting listeners: $e');
      setState(() => _isListening = false);
    }
  }

  void _processMessage(String message) {
    try {
      final List<String> segments = message.split('\n');
      for (var segment in segments) {
        if (segment.trim().isEmpty) continue;
        final decoded = jsonDecode(segment);
        if (decoded is Map<String, dynamic>) {
          setState(() {
            _alerts.insert(0, Alert.fromJson(decoded));
          });
        }
      }
    } catch (e) {
      debugPrint('Error parsing data: $e');
    }
  }

  @override
  void dispose() {
    _tcpServer?.close();
    _udpSocket?.close();
    super.dispose();
  }

  Color _getSeverityColor(String severity) {
    switch (severity.toLowerCase()) {
      case 'critical':
      case 'high':
        return Colors.redAccent;
      case 'medium':
        return Colors.orangeAccent;
      case 'low':
      default:
        return Colors.blueAccent;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('IDS Monitor', style: TextStyle(fontWeight: FontWeight.bold)),
            Text('Port 5005 (TCP/UDP)', style: TextStyle(fontSize: 12, color: Colors.grey)),
          ],
        ),
        actions: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16.0),
            child: Icon(
              Icons.circle,
              size: 12,
              color: _isListening ? Colors.green : Colors.red,
            ),
          ),
        ],
      ),
      body: _alerts.isEmpty
          ? Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.shield_outlined, size: 64, color: Colors.grey[700]),
                  const SizedBox(height: 16),
                  const Text('Waiting for alerts...', style: TextStyle(color: Colors.grey)),
                ],
              ),
            )
          : ListView.builder(
              padding: const EdgeInsets.all(12),
              itemCount: _alerts.length,
              itemBuilder: (context, index) {
                final alert = _alerts[index];
                final color = _getSeverityColor(alert.severity);

                return Card(
                  elevation: 2,
                  margin: const EdgeInsets.only(bottom: 12),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                    side: BorderSide(color: color.withValues(alpha: 0.3), width: 1),
                  ),
                  child: ListTile(
                    contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                    leading: Container(
                      width: 4,
                      decoration: BoxDecoration(
                        color: color,
                        borderRadius: BorderRadius.circular(2),
                      ),
                    ),
                    title: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          alert.event.toUpperCase(),
                          style: TextStyle(
                            fontWeight: FontWeight.bold,
                            color: color,
                            fontSize: 14,
                          ),
                        ),
                        Text(
                          DateFormat('HH:mm:ss').format(alert.timestamp),
                          style: const TextStyle(fontSize: 12, color: Colors.grey),
                        ),
                      ],
                    ),
                    subtitle: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const SizedBox(height: 4),
                        Text(
                          alert.message,
                          style: const TextStyle(fontSize: 16, color: Colors.white),
                        ),
                        if (alert.filePath.isNotEmpty) ...[
                          const SizedBox(height: 4),
                          Text(
                            'Path: ${alert.filePath}',
                            style: TextStyle(
                              fontSize: 12,
                              fontStyle: FontStyle.italic,
                              color: Colors.grey[400],
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                );
              },
            ),
    );
  }
}
