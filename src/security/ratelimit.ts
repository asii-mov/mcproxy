import { RateLimiterMemory, RateLimiterRes } from 'rate-limiter-flexible';

export interface RateLimitConfig {
  enabled: boolean;
  global?: {
    requests_per_minute?: number;
    requests_per_hour?: number;
  };
  per_client?: {
    requests_per_minute?: number;
    requests_per_hour?: number;
    burst_size?: number;
  };
  per_method?: {
    [method: string]: {
      requests_per_minute?: number;
      requests_per_hour?: number;
    };
  };
}

export class RateLimiter {
  private globalMinuteLimiter?: RateLimiterMemory;
  private globalHourLimiter?: RateLimiterMemory;
  private clientMinuteLimiter?: RateLimiterMemory;
  private clientHourLimiter?: RateLimiterMemory;
  private methodLimiters: Map<string, {
    minute?: RateLimiterMemory;
    hour?: RateLimiterMemory;
  }> = new Map();

  constructor(config: RateLimitConfig) {
    if (!config.enabled) return;

    // Global rate limiters
    if (config.global?.requests_per_minute) {
      this.globalMinuteLimiter = new RateLimiterMemory({
        points: config.global.requests_per_minute,
        duration: 60,
        blockDuration: 60
      });
    }

    if (config.global?.requests_per_hour) {
      this.globalHourLimiter = new RateLimiterMemory({
        points: config.global.requests_per_hour,
        duration: 3600,
        blockDuration: 3600
      });
    }

    // Per-client rate limiters
    if (config.per_client?.requests_per_minute) {
      this.clientMinuteLimiter = new RateLimiterMemory({
        points: config.per_client.requests_per_minute,
        duration: 60,
        blockDuration: 60
      });
    }

    if (config.per_client?.requests_per_hour) {
      this.clientHourLimiter = new RateLimiterMemory({
        points: config.per_client.requests_per_hour,
        duration: 3600,
        blockDuration: 3600
      });
    }

    // Per-method rate limiters
    if (config.per_method) {
      for (const [method, limits] of Object.entries(config.per_method)) {
        const methodLimiter: any = {};

        if (limits.requests_per_minute) {
          methodLimiter.minute = new RateLimiterMemory({
            points: limits.requests_per_minute,
            duration: 60,
            blockDuration: 60
          });
        }

        if (limits.requests_per_hour) {
          methodLimiter.hour = new RateLimiterMemory({
            points: limits.requests_per_hour,
            duration: 3600,
            blockDuration: 3600
          });
        }

        this.methodLimiters.set(method, methodLimiter);
      }
    }
  }

  public async checkLimit(clientId: string, method?: string): Promise<boolean> {
    try {
      // Check global limits
      if (this.globalMinuteLimiter) {
        await this.globalMinuteLimiter.consume('global', 1);
      }
      if (this.globalHourLimiter) {
        await this.globalHourLimiter.consume('global', 1);
      }

      // Check per-client limits
      if (this.clientMinuteLimiter) {
        await this.clientMinuteLimiter.consume(clientId, 1);
      }
      if (this.clientHourLimiter) {
        await this.clientHourLimiter.consume(clientId, 1);
      }

      // Check per-method limits
      if (method) {
        const methodLimiters = this.methodLimiters.get(method);
        if (methodLimiters) {
          if (methodLimiters.minute) {
            await methodLimiters.minute.consume(`${clientId}:${method}`, 1);
          }
          if (methodLimiters.hour) {
            await methodLimiters.hour.consume(`${clientId}:${method}`, 1);
          }
        }
      }

      return true;
    } catch (rejRes) {
      // Rate limit exceeded
      if (rejRes instanceof RateLimiterRes) {
        return false;
      }
      throw rejRes;
    }
  }

  public async getRemainingPoints(clientId: string, method?: string): Promise<{
    global?: { minute?: number; hour?: number };
    client?: { minute?: number; hour?: number };
    method?: { minute?: number; hour?: number };
  }> {
    const result: any = {};

    // Get global remaining points
    if (this.globalMinuteLimiter || this.globalHourLimiter) {
      result.global = {};
      if (this.globalMinuteLimiter) {
        try {
          const res = await this.globalMinuteLimiter.get('global');
          result.global.minute = res ? res.remainingPoints : this.globalMinuteLimiter.points;
        } catch {}
      }
      if (this.globalHourLimiter) {
        try {
          const res = await this.globalHourLimiter.get('global');
          result.global.hour = res ? res.remainingPoints : this.globalHourLimiter.points;
        } catch {}
      }
    }

    // Get client remaining points
    if (this.clientMinuteLimiter || this.clientHourLimiter) {
      result.client = {};
      if (this.clientMinuteLimiter) {
        try {
          const res = await this.clientMinuteLimiter.get(clientId);
          result.client.minute = res ? res.remainingPoints : this.clientMinuteLimiter.points;
        } catch {}
      }
      if (this.clientHourLimiter) {
        try {
          const res = await this.clientHourLimiter.get(clientId);
          result.client.hour = res ? res.remainingPoints : this.clientHourLimiter.points;
        } catch {}
      }
    }

    // Get method remaining points
    if (method) {
      const methodLimiters = this.methodLimiters.get(method);
      if (methodLimiters) {
        result.method = {};
        if (methodLimiters.minute) {
          try {
            const res = await methodLimiters.minute.get(`${clientId}:${method}`);
            result.method.minute = res ? res.remainingPoints : methodLimiters.minute.points;
          } catch {}
        }
        if (methodLimiters.hour) {
          try {
            const res = await methodLimiters.hour.get(`${clientId}:${method}`);
            result.method.hour = res ? res.remainingPoints : methodLimiters.hour.points;
          } catch {}
        }
      }
    }

    return result;
  }

  public async reset(clientId?: string): Promise<void> {
    if (clientId) {
      // Reset specific client
      if (this.clientMinuteLimiter) {
        await this.clientMinuteLimiter.delete(clientId);
      }
      if (this.clientHourLimiter) {
        await this.clientHourLimiter.delete(clientId);
      }

      // Reset client's method limits
      for (const [method, limiters] of this.methodLimiters) {
        if (limiters.minute) {
          await limiters.minute.delete(`${clientId}:${method}`);
        }
        if (limiters.hour) {
          await limiters.hour.delete(`${clientId}:${method}`);
        }
      }
    } else {
      // Reset all limits
      if (this.globalMinuteLimiter) {
        await this.globalMinuteLimiter.delete('global');
      }
      if (this.globalHourLimiter) {
        await this.globalHourLimiter.delete('global');
      }
    }
  }
}