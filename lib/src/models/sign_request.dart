import 'dart:typed_data';

import 'package:frosted/src/rust/api/tss_ed25519.dart';

class SignRequest {
  final String message;
  final List<KeyShard> keyShards;
  final Uint8List publicKeyPackage;

  SignRequest({
    required this.message,
    required this.keyShards,
    required this.publicKeyPackage,
  });

  Map<String, dynamic> toJson() {
    return {
      'message': message,
      'key_shards': keyShards
          .map((shard) => {
                'identifier': shard.identifier,
                'secret_share': shard.secretShare,
              })
          .toList(),
      'public_key_package': publicKeyPackage,
    };
  }
}
