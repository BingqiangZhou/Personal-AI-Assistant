import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:logger/logger.dart';

/// RSA加密服务
///
/// 用于在前端使用RSA公钥加密敏感数据（如API密钥）后再传输到后端
class RSAEncryptionService {
  final Logger _logger = Logger();

  String? _publicKeyPem;
  dynamic _parsedPublicKey;

  /// 设置RSA公钥（PEM格式）
  void setPublicKey(String publicKeyPem) {
    try {
      _publicKeyPem = publicKeyPem;
      // 使用encrypt包的RSAKeyParser解析PEM格式的公钥
      final parser = encrypt.RSAKeyParser();
      _parsedPublicKey = parser.parse(publicKeyPem);
      _logger.d('RSA public key loaded and parsed successfully');
    } catch (e) {
      _logger.e('Failed to parse RSA public key: $e');
      _parsedPublicKey = null;
    }
  }

  /// 获取当前设置的公钥
  String? get publicKey => _publicKeyPem;

  /// 检查公钥是否已加载并解析成功
  bool get isPublicKeyLoaded => _parsedPublicKey != null;

  /// 使用RSA公钥加密API密钥
  ///
  /// 返回Base64编码的加密数据
  String encryptApiKey(String apiKey) {
    if (_parsedPublicKey == null) {
      throw Exception('RSA public key not loaded or parsed. Call setPublicKey() first.');
    }

    try {
      final encrypter = encrypt.Encrypter(
        encrypt.RSA(publicKey: _parsedPublicKey),
      );

      // 加密并返回Base64编码
      final encrypted = encrypter.encrypt(apiKey);
      final base64Encoded = encrypted.base64;

      _logger.d('API key encrypted successfully (length: ${base64Encoded.length})');
      return base64Encoded;
    } catch (e) {
      _logger.e('Failed to encrypt API key: $e');
      rethrow;
    }
  }

  /// 清除当前加载的公钥
  void clear() {
    _publicKeyPem = null;
    _parsedPublicKey = null;
    _logger.d('RSA public key cleared');
  }
}

/// 全局单例
final rsaEncryptionService = RSAEncryptionService();
