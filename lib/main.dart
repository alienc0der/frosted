import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:frosted/src/rust/api/tss_ed25519.dart';
import 'package:frosted/src/rust/frb_generated.dart';
import 'package:frosted/src/services/keygen_service.dart';
import 'package:frosted/src/services/signature_service.dart';
import 'package:znn_sdk_dart/znn_sdk_dart.dart';

void main() async {
  await RustLib.init();
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final TextEditingController _messageController = TextEditingController();
  final TextEditingController _minSignersController = TextEditingController();
  final TextEditingController _maxSignersController = TextEditingController();
  bool? _isSignatureValidRust;
  bool? _isSignatureValidDart;
  bool _isVerifying = false;
  bool _isVerifyButtonEnabled = false;
  bool _isKeygenButtonEnabled = false;
  String _errorMessage = '';
  String _signature = '';

  KeygenResult? _keygenResult;

  List<bool> _selectedKeyShards = [];

  Future<void> performKeygen() async {
    setState(() {
      _isSignatureValidRust = null;
      _errorMessage = '';
    });

    final keygenService = KeygenService();

    try {
      int minSigners = int.parse(_minSignersController.text);
      int maxSigners = int.parse(_maxSignersController.text);

      if (minSigners > maxSigners || minSigners > 10 || maxSigners > 10) {
        throw 'Invalid signers count. Ensure minSigners <= maxSigners. maxSigners must be <= 10.';
      }

      _keygenResult = await keygenService.tssKeygen(maxSigners, minSigners);

      setState(() {
        _selectedKeyShards =
            List<bool>.filled(_keygenResult!.keyShards.length, false);
      });
    } catch (e) {
      print('Error: $e');
      setState(() {
        _errorMessage = e.toString();
        _isVerifying = false;
      });
    }

    setState(() {
      _isVerifying = false;
    });
  }

  Future<void> performKeysign() async {
    setState(() {
      _isSignatureValidRust = null;
      _isVerifying = true;
      _errorMessage = '';
    });

    if (_keygenResult == null) {
      setState(() {
        _errorMessage = 'Please generate key shards first.';
        return;
      });
    }

    final signatureService = SignatureService();
    String message = _messageController.text;

    List<KeyShard> selectedShards = [];
    for (int i = 0; i < _keygenResult!.keyShards.length; i++) {
      if (_selectedKeyShards[i]) {
        selectedShards.add(_keygenResult!.keyShards[i]);
      }
    }

    try {
      _signature = await signatureService.tssKeysign(
          selectedShards, message, _keygenResult!.publicKeyPackage);

      _isSignatureValidRust = await signatureService.tssVerifySignature(
          message, _signature, _keygenResult!.publicKeyPackage);

      _isSignatureValidDart = await Crypto.verify(
          base64Decode(_signature),
          Uint8List.fromList(message.codeUnits),
          Uint8List.fromList(_keygenResult!.groupPublicKey));

      print('Signature validation from Rust: $_isSignatureValidRust');
      print('Signature validation from Dart: $_isSignatureValidDart');
    } catch (e) {
      print('Error: $e');
      setState(() {
        _errorMessage = e.toString();
        _isSignatureValidRust = false;
        _isVerifying = false;
      });
    }

    setState(() {
      _isVerifying = false;
    });
  }

  void _updateKeygenButtonState() {
    bool isMinSignersNotEmpty = _minSignersController.text.isNotEmpty;
    bool isMaxSignersNotEmpty = _maxSignersController.text.isNotEmpty;

    bool shouldEnableButton = isMinSignersNotEmpty && isMaxSignersNotEmpty;
    if (shouldEnableButton != _isKeygenButtonEnabled) {
      setState(() {
        _isKeygenButtonEnabled = shouldEnableButton;
      });
    }
  }

  void _updateVerifyButtonState() {
    final isNotEmpty = _messageController.text.isNotEmpty;
    if (isNotEmpty != _isVerifyButtonEnabled) {
      setState(() {
        _isVerifyButtonEnabled = isNotEmpty;
      });
    }
  }

  @override
  void initState() {
    super.initState();
    _messageController.addListener(_updateVerifyButtonState);
    _minSignersController.addListener(_updateKeygenButtonState);
    _maxSignersController.addListener(_updateKeygenButtonState);
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('FROST TSS')),
        body: Container(
          padding: const EdgeInsets.all(16.0),
          color: _isSignatureValidRust == null
              ? null
              : (_isSignatureValidRust == true ? Colors.green : Colors.red),
          child: Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                ElevatedButton(
                  onPressed: !_isKeygenButtonEnabled ? null : performKeygen,
                  child: const Text('Generate Keys'),
                ),
                TextFormField(
                  controller: _minSignersController,
                  decoration: const InputDecoration(
                    labelText: 'Min Signers',
                  ),
                  keyboardType: TextInputType.number,
                ),
                TextFormField(
                  controller: _maxSignersController,
                  decoration: const InputDecoration(
                    labelText: 'Max Signers',
                  ),
                  keyboardType: TextInputType.number,
                ),
                const Spacer(),
                if (_keygenResult != null) _buildKeyShardChips(),
                const Spacer(),
                TextFormField(
                  controller: _messageController,
                  decoration: const InputDecoration(
                    labelText: 'Message',
                  ),
                ),
                const Spacer(),
                ElevatedButton(
                  onPressed: _isVerifying || !_isVerifyButtonEnabled
                      ? null
                      : performKeysign,
                  child: _isVerifying
                      ? const CircularProgressIndicator()
                      : const Text('Verify Signature'),
                ),
                if (_errorMessage.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(top: 8.0),
                    child: Text(
                      'Error: $_errorMessage',
                    ),
                  ),
                if (_isSignatureValidRust != null)
                  Text(_isSignatureValidRust == true
                      ? 'Signature is valid'
                      : 'Signature is invalid'),
              ],
            ),
          ),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _messageController.removeListener(_updateVerifyButtonState);
    _messageController.dispose();
    _minSignersController.removeListener(_updateKeygenButtonState);
    _minSignersController.dispose();
    _maxSignersController.removeListener(_updateKeygenButtonState);
    _maxSignersController.dispose();
    super.dispose();
  }

  Widget _buildKeyShardChips() {
    List<Widget> chips = [];
    for (int i = 0; i < (_keygenResult?.keyShards.length ?? 0); i++) {
      chips.add(ChoiceChip(
        label: Text('Key Shard ${i + 1}'),
        selected: _selectedKeyShards.isNotEmpty && _selectedKeyShards[i],
        onSelected: (bool selected) {
          setState(() {
            _selectedKeyShards[i] = selected;
          });
        },
      ));
    }
    return Wrap(
      spacing: 8.0,
      children: chips,
    );
  }
}
