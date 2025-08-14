import { readFileSync } from 'fs';
import { parse } from 'yaml';
import { resolve } from 'path';

export interface CharacterRules {
  allowed_ranges: number[][];
  blacklist: number[];
  ansi_escapes: {
    action: 'strip' | 'reject' | 'encode';
    log_attempts: boolean;
    pattern: string;
  };
  unicode: {
    normalize: boolean;
    homoglyphs: 'reject' | 'convert' | 'allow';
    invisible_chars: 'strip' | 'allow';
    rtl_override: 'reject' | 'allow';
  };
}

export interface PatternRule {
  name: string;
  description: string;
  regex: string;
  action: 'reject' | 'log' | 'sanitize' | 'strip';
  severity: 'critical' | 'high' | 'medium' | 'low';
  applies_to: string[];
}

export interface ToolPolicy {
  name: string;
  enabled: boolean;
  rate_limit?: string;
  restrictions?: {
    paths?: {
      allowed?: string[];
      denied?: string[];
    };
    urls?: {
      allowed?: string[];
      denied?: string[];
    };
    query_types?: {
      allowed?: string[];
      denied?: string[];
    };
  };
}

export interface Config {
  server: {
    host: string;
    port: number;
    tls: {
      enabled: boolean;
      cert_file?: string;
      key_file?: string;
    };
    max_connections: number;
    connection_timeout: string;
    idle_timeout: string;
    ws: {
      max_message_size: string;
      ping_interval: string;
      pong_timeout: string;
    };
  };
  sanitization: {
    mode: 'strict' | 'moderate' | 'permissive';
    character_rules: CharacterRules;
    validation: {
      max_message_size: string;
      max_prompt_length: number;
      max_tool_name_length: number;
      max_param_value_length: number;
      fields: {
        tool_name: {
          pattern: string;
          max_length: number;
        };
        tool_params: {
          strip_html: boolean;
          strip_scripts: boolean;
        };
      };
    };
  };
  patterns: PatternRule[];
  mcp_servers: {
    allowed: Array<{
      name: string;
      url: string;
      description?: string;
      fingerprint?: string;
      reconnect?: {
        enabled: boolean;
        max_attempts: number;
        initial_delay: string;
        max_delay: string;
      };
    }>;
    default: string;
    pool: {
      min_connections: number;
      max_connections: number;
      idle_timeout: string;
    };
  };
  tools: {
    default_policy: 'deny' | 'allow' | 'log';
    policies: ToolPolicy[];
  };
  rate_limiting: {
    enabled: boolean;
    global: {
      requests_per_second: number;
      burst_size: number;
    };
    per_client: {
      requests_per_minute: number;
      requests_per_hour: number;
      concurrent_requests: number;
      algorithm: 'sliding_window' | 'fixed_window';
    };
    per_tool_default: {
      requests_per_minute: number;
    };
    on_limit_exceeded: {
      action: 'reject' | 'queue' | 'throttle';
      response_code: number;
      retry_after: number;
      log_event: boolean;
    };
  };
  monitoring: {
    logging: {
      level: 'debug' | 'info' | 'warn' | 'error';
      format: 'json' | 'text';
      outputs: Array<{
        type: 'console' | 'file';
        format?: 'json' | 'text';
        level?: string;
        path?: string;
        max_size?: string;
        max_age?: string;
        compress?: boolean;
      }>;
      security: {
        enabled: boolean;
        file: string;
        force_log: boolean;
        events: string[];
      };
      audit: {
        enabled: boolean;
        file: string;
        include_payload: boolean;
        events: string[];
      };
    };
    metrics: {
      enabled: boolean;
      port: number;
      endpoint: string;
      collect: string[];
    };
    health: {
      enabled: boolean;
      endpoint: string;
      port: number;
      verbose: boolean;
    };
  };
  performance: {
    worker_threads: number;
    request_queue: {
      max_size: number;
      timeout: string;
    };
    cache: {
      enabled: boolean;
      type: 'memory' | 'redis';
      cache_sanitized: boolean;
      ttl: string;
      max_entries: number;
      max_size: string;
    };
    circuit_breaker: {
      enabled: boolean;
      failure_threshold: number;
      success_threshold: number;
      timeout: string;
      request_timeout: string;
    };
  };
  development: {
    debug: boolean;
    test_endpoints: boolean;
    simulation_mode: boolean;
    pretty_json: boolean;
    verbose_errors: boolean;
  };
}

export function loadConfig(configPath?: string): any {
  const fullPath = configPath || resolve(process.cwd(), 'mcproxy-config.yaml');
  
  try {
    const configContent = readFileSync(fullPath, 'utf8');
    return parse(configContent);
  } catch (error) {
    // Return default config if file doesn't exist
    return {
      proxy: {
        port: 8080,
        host: '0.0.0.0',
        mcp_server_url: 'ws://localhost:3000',
        max_connections: 100
      },
      sanitization: {
        character_whitelist: {
          enabled: true,
          allowed_ranges: [[0x20, 0x7E]],
          blacklist: [0x1B, 0x7F]
        },
        ansi_escapes: {
          enabled: true,
          action: 'strip'
        },
        patterns: {
          enabled: true,
          rules: []
        },
        strict_mode: false
      },
      rate_limiting: {
        enabled: false
      },
      logging: {
        level: 'info'
      }
    };
  }
}

export class ConfigLoader {
  private config: Config | null = null;
  private configPath: string;

  constructor(configPath?: string) {
    this.configPath = configPath || resolve(process.cwd(), 'mcproxy-config.yaml');
  }

  load(): Config {
    if (this.config) {
      return this.config;
    }

    try {
      const configContent = readFileSync(this.configPath, 'utf8');
      this.config = parse(configContent) as Config;
      this.validateConfig();
      this.applyEnvironmentOverrides();
      return this.config;
    } catch (error) {
      throw new Error(`Failed to load config from ${this.configPath}: ${error}`);
    }
  }

  private validateConfig(): void {
    if (!this.config) {
      throw new Error('Config is null');
    }

    if (!this.config.server?.port) {
      throw new Error('Server port is required');
    }

    if (!this.config.sanitization?.mode) {
      throw new Error('Sanitization mode is required');
    }

    if (!Array.isArray(this.config.patterns)) {
      throw new Error('Patterns must be an array');
    }

    for (const pattern of this.config.patterns) {
      try {
        new RegExp(pattern.regex);
      } catch (error) {
        throw new Error(`Invalid regex in pattern ${pattern.name}: ${error}`);
      }
    }
  }

  private applyEnvironmentOverrides(): void {
    if (!this.config) return;

    if (process.env.MCP_PROXY_PORT) {
      this.config.server.port = parseInt(process.env.MCP_PROXY_PORT, 10);
    }

    if (process.env.MCP_PROXY_HOST) {
      this.config.server.host = process.env.MCP_PROXY_HOST;
    }

    if (process.env.MCP_PROXY_STRICT_MODE) {
      this.config.sanitization.mode = process.env.MCP_PROXY_STRICT_MODE === 'true' ? 'strict' : 'permissive';
    }

    if (process.env.MCP_PROXY_LOG_LEVEL) {
      this.config.monitoring.logging.level = process.env.MCP_PROXY_LOG_LEVEL as any;
    }

    if (process.env.MCP_PROXY_METRICS_ENABLED) {
      this.config.monitoring.metrics.enabled = process.env.MCP_PROXY_METRICS_ENABLED === 'true';
    }

    if (process.env.MCP_PROXY_METRICS_PORT) {
      this.config.monitoring.metrics.port = parseInt(process.env.MCP_PROXY_METRICS_PORT, 10);
    }
  }

  getConfig(): Config {
    if (!this.config) {
      this.load();
    }
    return this.config!;
  }

  reload(): void {
    this.config = null;
    this.load();
  }
}