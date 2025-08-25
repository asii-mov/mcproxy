import { Logger } from '../monitoring/logger';

export interface KeyPattern {
  name: string;
  pattern: RegExp;
  description?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

export interface DetectionResult {
  detected: boolean;
  keys: Array<{
    value: string;
    type: string;
    position: number;
    length: number;
  }>;
}

export interface DetectorConfig {
  enabled?: boolean;
  builtinPatterns?: boolean;
  customPatterns?: Array<{
    name: string;
    pattern: string;
    description?: string;
  }>;
  minimumKeyLength?: number;
  maximumFalsePositiveRate?: number;
}

export class ApiKeyDetector {
  private patterns: KeyPattern[] = [];
  private config: DetectorConfig;
  private logger: Logger;
  private detectionStats: Map<string, number> = new Map();

  constructor(config: DetectorConfig = {}) {
    this.config = {
      enabled: config.enabled !== false,
      builtinPatterns: config.builtinPatterns !== false,
      customPatterns: config.customPatterns || [],
      minimumKeyLength: config.minimumKeyLength || 20,
      maximumFalsePositiveRate: config.maximumFalsePositiveRate || 0.01
    };

    this.logger = new Logger();
    this.initializePatterns();
  }

  private initializePatterns(): void {
    if (this.config.builtinPatterns) {
      this.patterns.push(...this.getBuiltinPatterns());
    }

    // Add custom patterns
    for (const custom of this.config.customPatterns || []) {
      try {
        this.patterns.push({
          name: custom.name,
          pattern: new RegExp(custom.pattern, 'g'),
          description: custom.description
        });
      } catch (error) {
        this.logger.error('Invalid custom API key pattern', {
          name: custom.name,
          pattern: custom.pattern,
          error: (error as Error).message
        });
      }
    }

    this.logger.info('API Key Detector initialized', {
      patternCount: this.patterns.length,
      builtinEnabled: this.config.builtinPatterns
    });
  }

  /**
   * Calculate Shannon entropy of a string
   */
  private calculateEntropy(str: string): number {
    const freq = new Map<string, number>();
    for (const char of str) {
      freq.set(char, (freq.get(char) || 0) + 1);
    }

    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / str.length;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }


  private getBuiltinPatterns(): KeyPattern[] {
    return [
      // OpenAI API Keys
      {
        name: 'openai',
        pattern: /\bsk-[a-zA-Z0-9]{48}\b/g,
        description: 'OpenAI API Key',
        severity: 'critical'
      },
      {
        name: 'openai_project',
        pattern: /\bsk-proj-[a-zA-Z0-9]{48}\b/g,
        description: 'OpenAI Project API Key',
        severity: 'critical'
      },
      
      // Anthropic API Keys (Updated pattern from TruffleHog)
      {
        name: 'anthropic',
        pattern: /\bsk-ant-[a-zA-Z0-9\-_=+/]{95,100}\b/g,
        description: 'Anthropic API Key',
        severity: 'critical'
      },
      
      // AWS Keys (Enhanced with ABIA and ACCA prefixes)
      {
        name: 'aws_access_key',
        pattern: /\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b/g,
        description: 'AWS Access Key ID',
        severity: 'critical'
      },
      {
        name: 'aws_secret_key',
        pattern: /\b[a-zA-Z0-9/+=]{40}\b/g,
        description: 'AWS Secret Access Key (potential)',
        severity: 'high'
      },
      
      // GitHub Tokens (Complete coverage from TruffleHog)
      {
        name: 'github_pat',
        pattern: /\bghp_[a-zA-Z0-9]{36,255}\b/g,
        description: 'GitHub Personal Access Token',
        severity: 'critical'
      },
      {
        name: 'github_oauth',
        pattern: /\bgho_[a-zA-Z0-9]{36,255}\b/g,
        description: 'GitHub OAuth Token',
        severity: 'critical'
      },
      {
        name: 'github_user_to_server',
        pattern: /\bghu_[a-zA-Z0-9]{36,255}\b/g,
        description: 'GitHub User-to-Server Token',
        severity: 'critical'
      },
      {
        name: 'github_server_to_server',
        pattern: /\bghs_[a-zA-Z0-9]{36,255}\b/g,
        description: 'GitHub Server-to-Server Token',
        severity: 'critical'
      },
      {
        name: 'github_refresh',
        pattern: /\bghr_[a-zA-Z0-9]{36,255}\b/g,
        description: 'GitHub Refresh Token',
        severity: 'critical'
      },
      {
        name: 'github_fine_grained_pat',
        pattern: /\bgithub_pat_[a-zA-Z0-9_]{36,255}\b/g,
        description: 'GitHub Fine-grained Personal Access Token',
        severity: 'critical'
      },
      
      // Google Cloud
      {
        name: 'gcp_api_key',
        pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
        description: 'Google Cloud API Key',
        severity: 'critical'
      },
      
      // Azure
      {
        name: 'azure_key',
        pattern: /\b[a-z0-9]{32}\b/g,
        description: 'Azure API Key (potential)',
        severity: 'medium'
      },
      
      // Slack (Enhanced patterns from TruffleHog)
      {
        name: 'slack_bot_token',
        pattern: /\bxoxb-[0-9]{12,13}-[0-9]{12,13}-[a-zA-Z0-9]{24}\b/g,
        description: 'Slack Bot Token',
        severity: 'high'
      },
      {
        name: 'slack_user_token',
        pattern: /\bxoxp-[0-9]{12,13}-[0-9]{12,13}-[0-9]{12,13}-[a-f0-9]{32}\b/g,
        description: 'Slack User Token',
        severity: 'high'
      },
      {
        name: 'slack_refresh_token',
        pattern: /\bxoxr-[a-zA-Z0-9\-]{146}\b/g,
        description: 'Slack Refresh Token',
        severity: 'high'
      },
      {
        name: 'slack_app_token',
        pattern: /\bxoxa-[a-zA-Z0-9\-]{146}\b/g,
        description: 'Slack App Token',
        severity: 'high'
      },
      {
        name: 'slack_webhook',
        pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/g,
        description: 'Slack Webhook URL',
        severity: 'high'
      },
      
      // Stripe (Complete with correct lengths)
      {
        name: 'stripe_secret_live',
        pattern: /\bsk_live_[a-zA-Z0-9]{99}\b/g,
        description: 'Stripe Live Secret Key',
        severity: 'critical'
      },
      {
        name: 'stripe_secret_test',
        pattern: /\bsk_test_[a-zA-Z0-9]{99}\b/g,
        description: 'Stripe Test Secret Key',
        severity: 'critical'
      },
      {
        name: 'stripe_public_live',
        pattern: /\bpk_live_[a-zA-Z0-9]{99}\b/g,
        description: 'Stripe Live Public Key',
        severity: 'medium'
      },
      {
        name: 'stripe_public_test',
        pattern: /\bpk_test_[a-zA-Z0-9]{99}\b/g,
        description: 'Stripe Test Public Key',
        severity: 'low'
      },
      {
        name: 'stripe_restricted_live',
        pattern: /\brk_live_[a-zA-Z0-9]{99}\b/g,
        description: 'Stripe Live Restricted Key',
        severity: 'critical'
      },
      {
        name: 'stripe_restricted_test',
        pattern: /\brk_test_[a-zA-Z0-9]{99}\b/g,
        description: 'Stripe Test Restricted Key',
        severity: 'high'
      },
      
      // SendGrid
      {
        name: 'sendgrid',
        pattern: /\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b/g,
        description: 'SendGrid API Key',
        severity: 'high'
      },
      
      // Twilio
      {
        name: 'twilio_api',
        pattern: /\bSK[a-z0-9]{32}\b/g,
        description: 'Twilio API Key',
        severity: 'high'
      },
      
      // JWT Tokens
      {
        name: 'jwt',
        pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
        description: 'JWT Token',
        severity: 'medium'
      },
      
      // Generic Bearer Tokens
      {
        name: 'bearer_token',
        pattern: /Bearer\s+[A-Za-z0-9\-_\.]{20,}/gi,
        description: 'Bearer Token',
        severity: 'medium'
      },
      
      // Discord
      {
        name: 'discord_bot_token',
        pattern: /\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b/g,
        description: 'Discord Bot Token',
        severity: 'high'
      },
      {
        name: 'discord_webhook',
        pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/(\d+)\/([A-Za-z0-9_-]{68})/g,
        description: 'Discord Webhook URL',
        severity: 'high'
      },
      
      // GitLab
      {
        name: 'gitlab_pat',
        pattern: /\bglpat-[a-zA-Z0-9\-=_]{20,22}\b/g,
        description: 'GitLab Personal Access Token',
        severity: 'critical'
      },
      {
        name: 'gitlab_pipeline',
        pattern: /\bglcbt-[a-zA-Z0-9\-=_]{20,22}\b/g,
        description: 'GitLab CI/CD Job Token',
        severity: 'high'
      },
      
      // Docker Hub
      {
        name: 'dockerhub_pat',
        pattern: /\bdckr_pat_[a-zA-Z0-9\-_=+]{36}\b/g,
        description: 'Docker Hub Personal Access Token',
        severity: 'high'
      },
      {
        name: 'dockerhub_oauth',
        pattern: /\bdckr_oat_[a-zA-Z0-9\-_=+]{36}\b/g,
        description: 'Docker Hub OAuth Token',
        severity: 'high'
      },
      
      // NPM
      {
        name: 'npm_token',
        pattern: /\bnpm_[a-zA-Z0-9]{36}\b/g,
        description: 'NPM Access Token',
        severity: 'high'
      },
      
      // Datadog
      {
        name: 'datadog_api_key',
        pattern: /\b[a-f0-9]{32}\b/g,
        description: 'Datadog API Key (potential)',
        severity: 'medium'
      },
      {
        name: 'datadog_app_key',
        pattern: /\b[a-f0-9]{40}\b/g,
        description: 'Datadog Application Key (potential)',
        severity: 'medium'
      },
      
      // YouTube
      {
        name: 'youtube_api_key',
        pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
        description: 'YouTube/Google API Key',
        severity: 'high'
      },
      
      // Doppler
      {
        name: 'doppler_config_token',
        pattern: /\bdp\.ct\.[a-zA-Z0-9]{40,44}\b/g,
        description: 'Doppler Config Token',
        severity: 'high'
      },
      {
        name: 'doppler_personal_token',
        pattern: /\bdp\.pt\.[a-zA-Z0-9]{40,44}\b/g,
        description: 'Doppler Personal Token',
        severity: 'critical'
      },
      {
        name: 'doppler_service_token',
        pattern: /\bdp\.st\.[a-zA-Z0-9]{40,44}\b/g,
        description: 'Doppler Service Token',
        severity: 'high'
      },
      {
        name: 'doppler_scim_token',
        pattern: /\bdp\.scim\.[a-zA-Z0-9]{40,44}\b/g,
        description: 'Doppler SCIM Token',
        severity: 'high'
      },
      
      // Database Connection Strings
      {
        name: 'mongodb_connection',
        pattern: /mongodb(?:\+srv)?:\/\/[^:]+:([^@]+)@[^/]+/g,
        description: 'MongoDB Connection String',
        severity: 'critical'
      },
      {
        name: 'postgresql_connection',
        pattern: /postgres(?:ql)?:\/\/[^:]+:([^@]+)@[^/]+/g,
        description: 'PostgreSQL Connection String',
        severity: 'critical'
      },
      {
        name: 'mysql_connection',
        pattern: /mysql:\/\/[^:]+:([^@]+)@[^/]+/g,
        description: 'MySQL Connection String',
        severity: 'critical'
      },
      {
        name: 'redis_connection',
        pattern: /redis:\/\/(?:[^:]*:)?([^@]+)@[^/]+/g,
        description: 'Redis Connection String',
        severity: 'critical'
      },
      
      // Generic API Key Patterns
      {
        name: 'generic_api_key',
        pattern: /\b(api[_\-]?key|apikey|api_secret|api[_\-]?token)[\s]*[=:]\s*['"]?[a-zA-Z0-9\-_]{20,}['"]?\b/gi,
        description: 'Generic API Key',
        severity: 'medium'
      },
      {
        name: 'generic_secret',
        pattern: /\b(secret|token|password|passwd|pwd)[\s]*[=:]\s*['"]?[a-zA-Z0-9\-_\.]{16,}['"]?\b/gi,
        description: 'Generic Secret',
        severity: 'medium'
      }
    ];
  }

  /**
   * Detect API keys in the input string
   */
  public detect(input: string): DetectionResult {
    if (!this.config.enabled || !input) {
      return { detected: false, keys: [] };
    }

    const detectedKeys: DetectionResult['keys'] = [];
    const seenKeys = new Set<string>();

    for (const pattern of this.patterns) {
      // Reset regex lastIndex for global patterns
      pattern.pattern.lastIndex = 0;
      
      let match;
      while ((match = pattern.pattern.exec(input)) !== null) {
        const key = match[0];
        
        // Skip if we've already detected this exact key
        if (seenKeys.has(key)) {
          continue;
        }
        
        // Skip if key is too short
        if (key.length < (this.config.minimumKeyLength || 20)) {
          continue;
        }
        
        // Additional validation to reduce false positives
        if (this.isFalsePositive(key, pattern.name)) {
          continue;
        }
        
        seenKeys.add(key);
        detectedKeys.push({
          value: key,
          type: pattern.name,
          position: match.index,
          length: key.length
        });
        
        // Update detection stats
        this.detectionStats.set(pattern.name, (this.detectionStats.get(pattern.name) || 0) + 1);
        
        this.logger.warn('API key detected', {
          type: pattern.name,
          position: match.index,
          keyLength: key.length,
          description: pattern.description
        });
      }
    }

    return {
      detected: detectedKeys.length > 0,
      keys: detectedKeys
    };
  }

  /**
   * Check if a detected key is likely a false positive
   */
  private isFalsePositive(key: string, type: string): boolean {
    // Common false positive patterns
    const falsePositivePatterns = [
      /^[0-9]+$/, // All numbers
      /^[A-Z]+$/, // All uppercase
      /^[a-z]+$/, // All lowercase
      /^(test|demo|example|sample|dummy|fake)/i, // Test keys
      /\.(jpg|jpeg|png|gif|pdf|doc|docx|txt|csv|json|xml)$/i // File extensions
    ];

    // Skip entropy check for hex-based keys (Datadog, etc)
    const hexBasedTypes = ['datadog_api_key', 'datadog_app_key'];
    if (!hexBasedTypes.includes(type)) {
      for (const pattern of falsePositivePatterns) {
        if (pattern.test(key)) {
          // Some patterns are okay for specific key types
          if (type === 'aws_secret_key' && /^[a-zA-Z0-9/+=]{40}$/.test(key)) {
            return false; // AWS secret keys can look like base64
          }
          return true;
        }
      }
    }

    // Apply entropy thresholds based on key type (from TruffleHog)
    const entropyThresholds: Record<string, number> = {
      'aws_access_key': 2.5,
      'aws_secret_key': 3.0,
      'github_pat': 3.5,
      'github_oauth': 3.5,
      'github_user_to_server': 3.5,
      'github_server_to_server': 3.5,
      'github_refresh': 3.5,
      'github_fine_grained_pat': 3.5,
      'openai': 3.5,
      'anthropic': 3.5,
      'generic_api_key': 3.0,
      'generic_secret': 3.0,
      'datadog_api_key': 2.5,
      'datadog_app_key': 2.5
    };

    // Check entropy for keys with defined thresholds
    const threshold = entropyThresholds[type];
    if (threshold !== undefined) {
      const entropy = this.calculateEntropy(key);
      if (entropy < threshold) {
        return true; // Low entropy suggests not a real key
      }
    }

    // Check for generic/potential types with default threshold
    if (type.includes('generic') || type.includes('potential')) {
      const entropy = this.calculateEntropy(key);
      if (entropy < 3.0) {
        return true;
      }
    }

    return false;
  }


  /**
   * Replace detected keys with placeholders
   */
  public replaceKeys(input: string, replacer: (key: string, type: string) => string): string {
    const detection = this.detect(input);
    if (!detection.detected) {
      return input;
    }

    // Sort keys by position in reverse order to maintain positions
    const sortedKeys = detection.keys.sort((a, b) => b.position - a.position);

    let result = input;
    for (const key of sortedKeys) {
      const placeholder = replacer(key.value, key.type);
      result = result.substring(0, key.position) + 
               placeholder + 
               result.substring(key.position + key.length);
    }

    return result;
  }

  /**
   * Get detection statistics
   */
  public getStats() {
    return {
      patternsLoaded: this.patterns.length,
      detectionsByType: Object.fromEntries(this.detectionStats),
      totalDetections: Array.from(this.detectionStats.values()).reduce((a, b) => a + b, 0)
    };
  }

  /**
   * Clear detection statistics
   */
  public clearStats(): void {
    this.detectionStats.clear();
  }

  /**
   * Add a custom pattern at runtime
   */
  public addPattern(name: string, pattern: string, description?: string): void {
    try {
      this.patterns.push({
        name,
        pattern: new RegExp(pattern, 'g'),
        description
      });
      this.logger.info('Added custom API key pattern', { name, pattern });
    } catch (error) {
      this.logger.error('Failed to add custom pattern', {
        name,
        pattern,
        error: (error as Error).message
      });
      throw error;
    }
  }
}