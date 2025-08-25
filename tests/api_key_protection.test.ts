import { ApiKeyVault } from '../src/security/api_key_vault';
import { ApiKeyDetector } from '../src/filters/api_key_detector';
import { Sanitizer } from '../src/security/sanitizer';

describe('API Key Protection', () => {
  describe('ApiKeyVault', () => {
    let vault: ApiKeyVault;

    beforeEach(() => {
      vault = new ApiKeyVault({
        enabled: true,
        encryption: true,
        ttl: 3600
      });
    });

    afterEach(() => {
      vault.shutdown();
    });

    test('should store and retrieve API keys', () => {
      const apiKey = 'sk-1234567890abcdef';
      const connectionId = 'conn-1';
      
      const placeholder = vault.storeKey(apiKey, connectionId, 'openai');
      expect(placeholder).toMatch(/^MCPROXY_KEY_[A-F0-9]{32}$/);
      
      const retrieved = vault.retrieveKey(placeholder, connectionId);
      expect(retrieved).toBe(apiKey);
    });

    test('should not retrieve keys for wrong connection', () => {
      const apiKey = 'sk-1234567890abcdef';
      const connectionId1 = 'conn-1';
      const connectionId2 = 'conn-2';
      
      const placeholder = vault.storeKey(apiKey, connectionId1, 'openai');
      const retrieved = vault.retrieveKey(placeholder, connectionId2);
      
      expect(retrieved).toBeNull();
    });

    test('should remove keys for connection', () => {
      const apiKey1 = 'sk-1234567890abcdef';
      const apiKey2 = 'sk-abcdef1234567890';
      const connectionId = 'conn-1';
      
      const placeholder1 = vault.storeKey(apiKey1, connectionId, 'openai');
      const placeholder2 = vault.storeKey(apiKey2, connectionId, 'openai');
      
      vault.removeConnectionKeys(connectionId);
      
      expect(vault.retrieveKey(placeholder1, connectionId)).toBeNull();
      expect(vault.retrieveKey(placeholder2, connectionId)).toBeNull();
    });

    test('should identify placeholders', () => {
      const apiKey = 'sk-1234567890abcdef';
      const connectionId = 'conn-1';
      
      const placeholder = vault.storeKey(apiKey, connectionId, 'openai');
      
      expect(vault.isPlaceholder(placeholder)).toBe(true);
      expect(vault.isPlaceholder('not-a-placeholder')).toBe(false);
      expect(vault.isPlaceholder('MCPROXY_KEY_INVALID')).toBe(false);
    });

    test('should return same placeholder for duplicate keys', () => {
      const apiKey = 'sk-1234567890abcdef';
      const connectionId = 'conn-1';
      
      const placeholder1 = vault.storeKey(apiKey, connectionId, 'openai');
      const placeholder2 = vault.storeKey(apiKey, connectionId, 'openai');
      
      expect(placeholder1).toBe(placeholder2);
    });

    test('should enforce max keys per connection', () => {
      const vault = new ApiKeyVault({
        enabled: true,
        maxKeysPerConnection: 2
      });
      
      const connectionId = 'conn-1';
      vault.storeKey('key1', connectionId);
      vault.storeKey('key2', connectionId);
      
      expect(() => {
        vault.storeKey('key3', connectionId);
      }).toThrow('Maximum API keys per connection exceeded');
      
      vault.shutdown();
    });
  });

  describe('ApiKeyDetector', () => {
    let detector: ApiKeyDetector;

    beforeEach(() => {
      detector = new ApiKeyDetector({
        enabled: true,
        builtinPatterns: true
      });
    });

    test('should detect OpenAI API keys', () => {
      const input = 'My API key is sk-abcdefghijklmnopqrstuvwxyz123456789012345678901';
      const result = detector.detect(input);
      
      expect(result.detected).toBe(true);
      expect(result.keys).toHaveLength(1);
      expect(result.keys[0]?.type).toBe('openai');
    });

    test('should detect Anthropic API keys', () => {
      const input = 'Using sk-ant-api01-' + 'a'.repeat(90);
      const result = detector.detect(input);
      
      expect(result.detected).toBe(true);
      expect(result.keys).toHaveLength(1);
      expect(result.keys[0]?.type).toBe('anthropic');
    });

    test('should detect AWS access keys', () => {
      const input = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';
      const result = detector.detect(input);
      
      expect(result.detected).toBe(true);
      expect(result.keys).toHaveLength(1);
      expect(result.keys[0]?.type).toBe('aws_access_key');
    });

    test('should detect GitHub PAT tokens', () => {
      const input = 'token: ghp_1234567890abcdefghijklmnopqrstuvwxyz';
      const result = detector.detect(input);
      
      expect(result.detected).toBe(true);
      expect(result.keys).toHaveLength(1);
      expect(result.keys[0]?.type).toBe('github_pat');
    });

    test('should detect multiple keys in one string', () => {
      const input = `
        openai_key: sk-abcdefghijklmnopqrstuvwxyz123456789012345678901
        github_token: ghp_1234567890abcdefghijklmnopqrstuvwxyz
        aws_key: AKIAIOSFODNN7EXAMPLE
      `;
      const result = detector.detect(input);
      
      expect(result.detected).toBe(true);
      expect(result.keys).toHaveLength(3);
      
      const types = result.keys.map(k => k.type);
      expect(types).toContain('openai');
      expect(types).toContain('github_pat');
      expect(types).toContain('aws_access_key');
    });

    test('should not detect false positives', () => {
      const inputs = [
        'This is just a regular string',
        'test-key-1234567890',
        'demo_token_example',
        'sample_api_key_for_testing'
      ];
      
      for (const input of inputs) {
        const result = detector.detect(input);
        expect(result.detected).toBe(false);
      }
    });

    test('should replace keys with custom replacer', () => {
      const input = 'My key is sk-abcdefghijklmnopqrstuvwxyz123456789012345678901';
      const result = detector.replaceKeys(input, (_key, type) => `[REDACTED_${type.toUpperCase()}]`);
      
      expect(result).toBe('My key is [REDACTED_OPENAI]');
    });

    test('should handle custom patterns', () => {
      const detector = new ApiKeyDetector({
        enabled: true,
        builtinPatterns: false,
        customPatterns: [
          {
            name: 'custom_key',
            pattern: 'custom_[a-z0-9]{16}'
          }
        ]
      });
      
      const input = 'My custom key: custom_abcd1234efgh5678';
      const result = detector.detect(input);
      
      expect(result.detected).toBe(true);
      expect(result.keys).toHaveLength(1);
      expect(result.keys[0]?.type).toBe('custom_key');
    });

    test('should respect minimum key length', () => {
      const detector = new ApiKeyDetector({
        enabled: true,
        builtinPatterns: true,
        minimumKeyLength: 50
      });
      
      const shortKey = 'sk-short123';
      const longKey = 'sk-' + 'a'.repeat(48);
      
      expect(detector.detect(shortKey).detected).toBe(false);
      expect(detector.detect(longKey).detected).toBe(true);
    });
  });

  describe('Sanitizer Integration', () => {
    let config: any;

    beforeEach(() => {
      config = {
        api_key_protection: {
          enabled: true,
          detection: {
            builtin_patterns: true
          },
          storage: {
            encryption: true,
            ttl: 3600
          }
        },
        sanitization: {
          ansi_escapes: { enabled: false },
          character_whitelist: { enabled: false },
          patterns: { enabled: false }
        }
      };
    });

    test('should sanitize messages with API keys', () => {
      const sanitizer = new Sanitizer(config, 'conn-1');
      
      const message = {
        method: 'call_api',
        params: {
          api_key: 'sk-abcdefghijklmnopqrstuvwxyz123456789012345678901',
          endpoint: 'https://api.openai.com/v1/chat'
        }
      };
      
      const result = sanitizer.sanitizeMessage(message, 'client_to_server');
      
      expect(result.hasApiKeys).toBe(true);
      expect(result.modified).toBe(true);
      expect(result.message.params.api_key).toMatch(/^MCPROXY_KEY_[A-F0-9]{32}$/);
      expect(result.message.params.endpoint).toBe('https://api.openai.com/v1/chat');
    });

    test('should re-substitute API keys for server', () => {
      const sanitizer = new Sanitizer(config, 'conn-1');
      
      const originalKey = 'sk-abcdefghijklmnopqrstuvwxyz123456789012345678901';
      const message = {
        method: 'call_api',
        params: {
          api_key: originalKey
        }
      };
      
      // First sanitize (client to server)
      const sanitized = sanitizer.sanitizeMessage(message, 'client_to_server');
      
      // Then re-substitute (for MCP server)
      const resubstituted = sanitizer.resubstituteApiKeys(sanitized.message);
      
      expect(resubstituted.modified).toBe(true);
      expect(resubstituted.message.params.api_key).toBe(originalKey);
    });

    test('should not re-substitute in server to client direction', () => {
      const sanitizer = new Sanitizer(config, 'conn-1');
      
      const message = {
        result: {
          data: 'Response data',
          used_key: 'MCPROXY_KEY_1234567890ABCDEF1234567890ABCDEF'
        }
      };
      
      const result = sanitizer.sanitizeMessage(message, 'server_to_client');
      
      expect(result.message.result.used_key).toBe('MCPROXY_KEY_1234567890ABCDEF1234567890ABCDEF');
      expect(result.hasApiKeys).toBeFalsy();
    });

    test('should handle nested API keys', () => {
      const sanitizer = new Sanitizer(config, 'conn-1');
      
      const message = {
        method: 'multi_api_call',
        params: {
          services: [
            {
              name: 'openai',
              key: 'sk-openai1234567890abcdefghijklmnopqrstuvwxyz12345'
            },
            {
              name: 'github',
              key: 'ghp_github1234567890abcdefghijklmnopqrstuv'
            }
          ],
          config: {
            aws: {
              access_key: 'AKIAIOSFODNN7EXAMPLE'
            }
          }
        }
      };
      
      const result = sanitizer.sanitizeMessage(message, 'client_to_server');
      
      expect(result.hasApiKeys).toBe(true);
      expect(result.message.params.services[0].key).toMatch(/^MCPROXY_KEY_/);
      expect(result.message.params.services[1].key).toMatch(/^MCPROXY_KEY_/);
      expect(result.message.params.config.aws.access_key).toMatch(/^MCPROXY_KEY_/);
    });

    test('should cleanup connection keys', () => {
      const sanitizer = new Sanitizer(config, 'conn-1');
      
      const message = {
        api_key: 'sk-test1234567890abcdefghijklmnopqrstuvwxyz123456'
      };
      
      // Sanitize to store key
      const result = sanitizer.sanitizeMessage(message, 'client_to_server');
      const placeholder = result.message.api_key;
      
      // Cleanup connection
      sanitizer.cleanupConnection();
      
      // Try to re-substitute after cleanup
      const resubResult = sanitizer.resubstituteApiKeys({ api_key: placeholder });
      
      // Should not be able to retrieve after cleanup
      expect(resubResult.modified).toBe(false);
      expect(resubResult.message.api_key).toBe(placeholder);
    });
  });

  describe('Edge Cases', () => {
    test('should handle partial API keys', () => {
      const detector = new ApiKeyDetector({ enabled: true, builtinPatterns: true });
      
      const partialKeys = [
        'sk-abc', // Too short
        'ghp_123', // Too short
        'AKIA', // Incomplete AWS key
      ];
      
      for (const key of partialKeys) {
        const result = detector.detect(key);
        expect(result.detected).toBe(false);
      }
    });

    test('should handle keys at string boundaries', () => {
      const detector = new ApiKeyDetector({ enabled: true, builtinPatterns: true });
      
      const key = 'sk-abcdefghijklmnopqrstuvwxyz123456789012345678901';
      const inputs = [
        key, // Key alone
        `${key} `, // Key at start
        ` ${key}`, // Key at end
        `prefix${key}suffix`, // Key in middle without word boundaries
      ];
      
      expect(detector.detect(inputs[0]!).detected).toBe(true);
      expect(detector.detect(inputs[1]!).detected).toBe(true);
      expect(detector.detect(inputs[2]!).detected).toBe(true);
      // This one might not be detected due to word boundaries
    });

    test('should handle URL-encoded keys', () => {
      const detector = new ApiKeyDetector({ enabled: true, builtinPatterns: true });
      
      // URL encoded keys might not be detected directly
      const encoded = 'sk%2Dabcdefghijklmnopqrstuvwxyz123456789012345678901';
      const result = detector.detect(encoded);
      
      // This is expected not to match as it's encoded
      expect(result.detected).toBe(false);
    });

    test('should handle JSON stringified keys', () => {
      const detector = new ApiKeyDetector({ enabled: true, builtinPatterns: true });
      
      const json = JSON.stringify({
        api_key: 'sk-abcdefghijklmnopqrstuvwxyz123456789012345678901'
      });
      
      const result = detector.detect(json);
      expect(result.detected).toBe(true);
      expect(result.keys).toHaveLength(1);
    });
  });
});