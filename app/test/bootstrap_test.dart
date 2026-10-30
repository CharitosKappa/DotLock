import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault/main.dart';

void main() {
  testWidgets('boots an empty app without vault content', (tester) async {
    await tester.pumpWidget(const DotLockApp());

    expect(tester.takeException(), isNull);
    expect(find.byType(Text), findsNothing);
  });
}
