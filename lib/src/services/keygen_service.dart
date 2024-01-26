import 'package:frosted/src/rust/api/tss_ed25519.dart';

class KeygenService {
  Future<KeygenResult> tssKeygen(int maxSigners, int minSigners) async {
    try {
      final keygenResult =
          await keygen(maxSigners: maxSigners, minSigners: minSigners);
      return keygenResult;
    } catch (e) {
      print('Error generating keys: $e');
      rethrow;
    }
  }
}
