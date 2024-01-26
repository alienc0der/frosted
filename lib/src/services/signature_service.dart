import 'dart:convert';
import 'dart:typed_data';

import 'package:frosted/src/models/sign_request.dart';
import 'package:frosted/src/rust/api/tss_ed25519.dart';

class SignatureService {
  Future<String> tssKeysign(List<KeyShard> keyShards, String message,
      Uint8List publicKeyPackage) async {
    try {
      final request = SignRequest(
        keyShards: keyShards,
        message: message,
        publicKeyPackage: publicKeyPackage,
      );
      final signature = await keysign(serializedRequest: jsonEncode(request));
      return signature;
    } catch (e) {
      print('Error during keysign: $e');
      rethrow;
    }
  }

  Future<bool> tssVerifySignature(String message, String signatureBase64,
      Uint8List publicKeyPackage) async {
    try {
      final request = VerifyRequest(
        message: message,
        signatureBase64: signatureBase64,
        publicKeyPackage: publicKeyPackage,
      );
      final isSignatureValid = await verifySignature(request: request);
      return isSignatureValid;
    } catch (e) {
      print('Error during signature verification: $e');
      rethrow;
    }
  }
}
