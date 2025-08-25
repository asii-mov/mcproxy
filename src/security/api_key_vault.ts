import { randomBytes, createCipheriv, createDecipheriv, scryptSync } from 'crypto';
import { Logger } from '../monitoring/logger';

export interface StoredKey {
  placeholder: string;
  encryptedKey: string;
  iv: string;
  createdAt: number;
  lastAccessed: number;
  connectionId: string;
  keyType?: string;
}

export interface VaultConfig {
  enabled?: boolean;
  encryption?: boolean;
  ttl?: number; // seconds
  maxKeysPerConnection?: number;
}

export class ApiKeyVault {
  private vault: Map<string, StoredKey> = new Map();
  private keyToPlaceholder: Map<string, string> = new Map();
  private connectionKeys: Map<string, Set<string>> = new Map();
  private config: VaultConfig;
  private logger: Logger;
  private encryptionKey: Buffer;
  private cleanupInterval?: NodeJS.Timeout;

  constructor(config: VaultConfig = {}) {
    this.config = {
      enabled: config.enabled !== false,
      encryption: config.encryption !== false,
      ttl: config.ttl || 3600,
      maxKeysPerConnection: config.maxKeysPerConnection || 100
    };
    
    this.logger = new Logger();
    
    // Generate encryption key from environment or create a random one
    const secret = process.env.MCPROXY_VAULT_SECRET || randomBytes(32).toString('hex');
    this.encryptionKey = scryptSync(secret, 'mcproxy-salt', 32);
    
    // Start cleanup interval
    if (this.config.ttl && this.config.ttl > 0) {
      this.cleanupInterval = setInterval(() => this.cleanupExpiredKeys(), 60000); // Every minute
    }
  }

  /**
   * Store an API key and return a placeholder
   */
  public storeKey(apiKey: string, connectionId: string, keyType?: string): string {
    if (!this.config.enabled) {
      return apiKey;
    }

    // Check if we already have a placeholder for this key
    const existingPlaceholder = this.keyToPlaceholder.get(apiKey);
    if (existingPlaceholder) {
      const stored = this.vault.get(existingPlaceholder);
      if (stored) {
        stored.lastAccessed = Date.now();
        return existingPlaceholder;
      }
    }

    // Check connection key limit
    const connectionKeySet = this.connectionKeys.get(connectionId) || new Set();
    if (connectionKeySet.size >= (this.config.maxKeysPerConnection || 100)) {
      this.logger.warn('Connection key limit reached', {
        connectionId,
        limit: this.config.maxKeysPerConnection
      });
      throw new Error('Maximum API keys per connection exceeded');
    }

    // Generate unique placeholder
    const placeholder = `MCPROXY_KEY_${randomBytes(16).toString('hex').toUpperCase()}`;
    
    // Encrypt the key if encryption is enabled
    let encryptedKey = apiKey;
    let iv = '';
    
    if (this.config.encryption) {
      iv = randomBytes(16).toString('hex');
      const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, Buffer.from(iv, 'hex'));
      encryptedKey = cipher.update(apiKey, 'utf8', 'hex') + cipher.final('hex');
      encryptedKey += ':' + cipher.getAuthTag().toString('hex');
    }

    // Store the key
    const storedKey: StoredKey = {
      placeholder,
      encryptedKey,
      iv,
      createdAt: Date.now(),
      lastAccessed: Date.now(),
      connectionId,
      keyType
    };

    this.vault.set(placeholder, storedKey);
    this.keyToPlaceholder.set(apiKey, placeholder);
    
    // Track connection keys
    if (!this.connectionKeys.has(connectionId)) {
      this.connectionKeys.set(connectionId, new Set());
    }
    this.connectionKeys.get(connectionId)!.add(placeholder);

    this.logger.info('API key stored in vault', {
      connectionId,
      placeholder,
      keyType
    });

    return placeholder;
  }

  /**
   * Retrieve an API key using its placeholder
   */
  public retrieveKey(placeholder: string, connectionId: string): string | null {
    if (!this.config.enabled) {
      return placeholder;
    }

    const stored = this.vault.get(placeholder);
    if (!stored) {
      return null;
    }

    // Verify connection ownership
    if (stored.connectionId !== connectionId) {
      this.logger.warn('Unauthorized key access attempt', {
        connectionId,
        placeholder,
        ownerConnectionId: stored.connectionId
      });
      return null;
    }

    // Check TTL
    if (this.config.ttl && this.config.ttl > 0) {
      const age = (Date.now() - stored.createdAt) / 1000;
      if (age > this.config.ttl) {
        this.logger.info('Key expired', {
          placeholder,
          ageSeconds: age,
          ttl: this.config.ttl
        });
        this.removeKey(placeholder);
        return null;
      }
    }

    // Update last accessed time
    stored.lastAccessed = Date.now();

    // Decrypt the key if encryption is enabled
    let apiKey = stored.encryptedKey;
    
    if (this.config.encryption && stored.iv) {
      try {
        const parts = stored.encryptedKey.split(':');
        if (parts.length !== 2) {
          throw new Error('Invalid encrypted key format');
        }
        const [encrypted, authTag] = parts;
        const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, Buffer.from(stored.iv, 'hex'));
        decipher.setAuthTag(Buffer.from(authTag!, 'hex'));
        apiKey = decipher.update(encrypted!, 'hex', 'utf8') + decipher.final('utf8');
      } catch (error) {
        this.logger.error('Failed to decrypt API key', {
          placeholder,
          error: (error as Error).message
        });
        return null;
      }
    }

    return apiKey;
  }

  /**
   * Remove a key from the vault
   */
  public removeKey(placeholder: string): void {
    const stored = this.vault.get(placeholder);
    if (stored) {
      // Remove from connection tracking
      const connectionKeys = this.connectionKeys.get(stored.connectionId);
      if (connectionKeys) {
        connectionKeys.delete(placeholder);
        if (connectionKeys.size === 0) {
          this.connectionKeys.delete(stored.connectionId);
        }
      }
      
      // Remove from reverse mapping
      if (this.config.encryption) {
        // Can't reverse lookup encrypted keys efficiently
        for (const [key, ph] of this.keyToPlaceholder.entries()) {
          if (ph === placeholder) {
            this.keyToPlaceholder.delete(key);
            break;
          }
        }
      }
      
      // Remove from vault
      this.vault.delete(placeholder);
      
      this.logger.debug('Key removed from vault', { placeholder });
    }
  }

  /**
   * Remove all keys for a connection
   */
  public removeConnectionKeys(connectionId: string): void {
    const connectionKeys = this.connectionKeys.get(connectionId);
    if (connectionKeys) {
      for (const placeholder of connectionKeys) {
        this.removeKey(placeholder);
      }
      this.connectionKeys.delete(connectionId);
      
      this.logger.info('All keys removed for connection', {
        connectionId,
        keysRemoved: connectionKeys.size
      });
    }
  }

  /**
   * Check if a string is a placeholder
   */
  public isPlaceholder(value: string): boolean {
    return value.startsWith('MCPROXY_KEY_') && this.vault.has(value);
  }

  /**
   * Clean up expired keys
   */
  private cleanupExpiredKeys(): void {
    if (!this.config.ttl || this.config.ttl <= 0) return;

    const now = Date.now();
    const expired: string[] = [];

    for (const [placeholder, stored] of this.vault.entries()) {
      const age = (now - stored.createdAt) / 1000;
      if (this.config.ttl && age > this.config.ttl) {
        expired.push(placeholder);
      }
    }

    for (const placeholder of expired) {
      this.removeKey(placeholder);
    }

    if (expired.length > 0) {
      this.logger.info('Cleaned up expired keys', {
        count: expired.length
      });
    }
  }

  /**
   * Get vault statistics
   */
  public getStats() {
    return {
      totalKeys: this.vault.size,
      connectionsWithKeys: this.connectionKeys.size,
      encryptionEnabled: this.config.encryption,
      ttlSeconds: this.config.ttl
    };
  }

  /**
   * Shutdown the vault
   */
  public shutdown(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    
    this.vault.clear();
    this.keyToPlaceholder.clear();
    this.connectionKeys.clear();
    
    this.logger.info('API Key Vault shutdown');
  }
}