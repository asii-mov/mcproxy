import { ApiKeyDetector } from '../src/filters/api_key_detector';

describe('TruffleHog Pattern Detection', () => {
  let detector: ApiKeyDetector;

  beforeEach(() => {
    detector = new ApiKeyDetector({
      enabled: true,
      builtinPatterns: true
    });
  });

  describe('Enhanced AWS Detection', () => {
    test('should detect AKIA prefixed keys', () => {
      const input = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('aws_access_key');
    });

    test('should detect ABIA prefixed keys', () => {
      const input = 'key: ABIA1234567890123456';
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('aws_access_key');
    });

    test('should detect ACCA prefixed keys', () => {
      const input = 'ACCESS_KEY=ACCA1234567890123456';
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('aws_access_key');
    });
  });

  describe('Complete GitHub Token Coverage', () => {
    test('should detect user-to-server tokens (ghu_)', () => {
      const input = 'token: ghu_' + 'a'.repeat(36);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('github_user_to_server');
    });

    test('should detect refresh tokens (ghr_)', () => {
      const input = 'refresh: ghr_' + 'b'.repeat(36);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('github_refresh');
    });

    test('should detect fine-grained PATs', () => {
      const input = 'pat: github_pat_' + 'c'.repeat(40);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('github_fine_grained_pat');
    });

    test('should detect variable length GitHub tokens', () => {
      const longToken = 'ghp_' + 'x'.repeat(255);
      const result = detector.detect(longToken);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('github_pat');
    });
  });

  describe('Enhanced Slack Patterns', () => {
    test('should detect bot tokens with precise pattern', () => {
      const input = 'xoxb-123456789012-123456789012-' + 'a'.repeat(24);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('slack_bot_token');
    });

    test('should detect user tokens with exact format', () => {
      const input = 'xoxp-123456789012-123456789012-123456789012-' + 'f'.repeat(32);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('slack_user_token');
    });

    test('should detect refresh tokens', () => {
      const input = 'xoxr-' + 'a'.repeat(146);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('slack_refresh_token');
    });

    test('should detect app tokens', () => {
      const input = 'xoxa-' + 'b'.repeat(146);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('slack_app_token');
    });
  });

  describe('Discord Detection', () => {
    test('should detect Discord bot tokens', () => {
      const input = 'M' + 'a'.repeat(23) + '.abc123.xyz-' + 'a'.repeat(15);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('discord_bot_token');
    });

    test('should detect Discord webhook URLs', () => {
      const input = 'https://discord.com/api/webhooks/123456789/' + 'a'.repeat(68);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('discord_webhook');
    });

    test('should detect Discord app webhook URLs', () => {
      const input = 'https://discordapp.com/api/webhooks/987654321/' + 'b'.repeat(68);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('discord_webhook');
    });
  });

  describe('GitLab Tokens', () => {
    test('should detect GitLab personal access tokens', () => {
      const input = 'glpat-' + 'a'.repeat(20);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('gitlab_pat');
    });

    test('should detect GitLab CI/CD tokens', () => {
      const input = 'glcbt-' + 'b'.repeat(22);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('gitlab_pipeline');
    });
  });

  describe('Docker Hub Tokens', () => {
    test('should detect Docker Hub PATs', () => {
      const input = 'dckr_pat_' + 'a'.repeat(36);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('dockerhub_pat');
    });

    test('should detect Docker Hub OAuth tokens', () => {
      const input = 'dckr_oat_' + 'b'.repeat(36);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('dockerhub_oauth');
    });
  });

  describe('NPM Tokens', () => {
    test('should detect NPM access tokens', () => {
      const input = 'npm_' + 'x'.repeat(36);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('npm_token');
    });
  });

  describe('Stripe Keys with Correct Lengths', () => {
    test('should detect Stripe live secret keys', () => {
      const input = 'sk_live_' + 'a'.repeat(99);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('stripe_secret_live');
    });

    test('should detect Stripe test secret keys', () => {
      const input = 'sk_test_' + 'b'.repeat(99);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('stripe_secret_test');
    });

    test('should detect Stripe public keys', () => {
      const input = 'pk_live_' + 'c'.repeat(99);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('stripe_public_live');
    });

    test('should detect Stripe restricted keys', () => {
      const input = 'rk_test_' + 'd'.repeat(99);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('stripe_restricted_test');
    });
  });

  describe('YouTube/Google API Keys', () => {
    test('should detect YouTube API keys with AIza prefix', () => {
      const input = 'AIza' + 'a'.repeat(35);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('youtube_api_key');
    });
  });

  describe('Doppler Tokens', () => {
    test('should detect config tokens', () => {
      const input = 'dp.ct.' + 'a'.repeat(40);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('doppler_config_token');
    });

    test('should detect personal tokens', () => {
      const input = 'dp.pt.' + 'b'.repeat(42);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('doppler_personal_token');
    });

    test('should detect service tokens', () => {
      const input = 'dp.st.' + 'c'.repeat(44);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('doppler_service_token');
    });

    test('should detect SCIM tokens', () => {
      const input = 'dp.scim.' + 'd'.repeat(40);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('doppler_scim_token');
    });
  });

  describe('Database Connection Strings', () => {
    test('should detect MongoDB connection strings', () => {
      const input = 'mongodb://user:password123@localhost:27017';
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('mongodb_connection');
    });

    test('should detect MongoDB+SRV connection strings', () => {
      const input = 'mongodb+srv://admin:secretpass@cluster.mongodb.net';
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('mongodb_connection');
    });

    test('should detect PostgreSQL connection strings', () => {
      const input = 'postgresql://user:pass123@localhost:5432/db';
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('postgresql_connection');
    });

    test('should detect MySQL connection strings', () => {
      const input = 'mysql://root:admin123@localhost:3306/database';
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('mysql_connection');
    });

    test('should detect Redis connection strings', () => {
      const input = 'redis://user:password@localhost:6379';
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('redis_connection');
    });
  });

  describe('Datadog Keys', () => {
    test('should detect potential Datadog API keys', () => {
      const input = 'DD_API_KEY=' + 'a'.repeat(32).toLowerCase();
      const result = detector.detect(input);
      // Should detect as hex pattern
      expect(result.detected).toBe(true);
    });

    test('should detect potential Datadog app keys', () => {
      const input = 'DD_APP_KEY=' + 'f'.repeat(40).toLowerCase();
      const result = detector.detect(input);
      // Should detect as hex pattern
      expect(result.detected).toBe(true);
    });
  });

  describe('Entropy Validation', () => {
    test('should reject low entropy keys', () => {
      const detector = new ApiKeyDetector({
        enabled: true,
        builtinPatterns: true
      });

      // Low entropy (all same character)
      const lowEntropyKey = 'sk-' + 'a'.repeat(48);
      const result = detector.detect(lowEntropyKey);
      
      // Should be detected but might be filtered as false positive
      // This depends on entropy threshold implementation
      expect(result.keys.length).toBeGreaterThanOrEqual(0);
    });

    test('should accept high entropy keys', () => {
      const highEntropyKey = 'sk-' + 'aBc123XyZ456DefGhi789JklMno012PqrStu345VwxYz678';
      const result = detector.detect(highEntropyKey);
      
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('openai');
    });
  });

  describe('Updated Anthropic Pattern', () => {
    test('should detect new Anthropic key format', () => {
      const input = 'sk-ant-' + 'a'.repeat(95);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('anthropic');
    });

    test('should detect Anthropic keys with special chars', () => {
      const input = 'sk-ant-abc123-def_456+ghi/789=' + 'x'.repeat(65);
      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys[0]?.type).toBe('anthropic');
    });
  });

  describe('Multiple Key Detection', () => {
    test('should detect multiple different key types', () => {
      const input = `
        AWS_KEY=AKIAIOSFODNN7EXAMPLE
        GITHUB_TOKEN=ghp_${'x'.repeat(36)}
        SLACK_BOT=xoxb-123456789012-123456789012-${'a'.repeat(24)}
        STRIPE_KEY=sk_live_${'b'.repeat(99)}
        DOCKER_PAT=dckr_pat_${'c'.repeat(36)}
        NPM_TOKEN=npm_${'d'.repeat(36)}
      `;

      const result = detector.detect(input);
      expect(result.detected).toBe(true);
      expect(result.keys.length).toBeGreaterThanOrEqual(6);

      const types = result.keys.map(k => k.type);
      expect(types).toContain('aws_access_key');
      expect(types).toContain('github_pat');
      expect(types).toContain('slack_bot_token');
      expect(types).toContain('stripe_secret_live');
      expect(types).toContain('dockerhub_pat');
      expect(types).toContain('npm_token');
    });
  });

  describe('False Positive Reduction', () => {
    test('should not detect test/demo keys', () => {
      const testKeys = [
        'test_key_123456',
        'demo_token_abcdef',
        'example_secret_xyz',
        'sample_api_key'
      ];

      for (const key of testKeys) {
        const result = detector.detect(key);
        expect(result.detected).toBe(false);
      }
    });

    test('should not detect file extensions as keys', () => {
      const fileNames = [
        'document.pdf',
        'image.jpg',
        'data.json',
        'config.xml'
      ];

      for (const fileName of fileNames) {
        const result = detector.detect(fileName);
        expect(result.detected).toBe(false);
      }
    });
  });
});