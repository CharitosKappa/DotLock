import 'package:flutter/material.dart';

void main() {
  runApp(const DotLockApp());
}

class DotLockApp extends StatelessWidget {
  const DotLockApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(home: Scaffold(body: SizedBox.shrink()));
  }
}
