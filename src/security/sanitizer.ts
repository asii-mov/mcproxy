import { Config } from '../config/loader';
import { Logger } from '../monitoring/logger';
import { AnsiFilter } from '../filters/ansi_filter';
import { CharacterWhitelist } from '../filters/char_whitelist';
import { PatternMatcher } from '../filters/pattern_match';

export interface SanitizationResult {
  success: boolean;
  sanitized: string | null;
  errors: string[];
  warnings: string[];
  stats: {
    originalLength: number;
    sanitizedLength: number;
    charactersRemoved: number;
    patternsDetected: number;
    ansiSequencesRemoved: boolean;
  };
}

export class Sanitizer {
  private ansiFilter: AnsiFilter;
  private charWhitelist: CharacterWhitelist;
  private patternMatcher: PatternMatcher;
  private config: Config;
  private logger: Logger;

  constructor(config: any) {
    this.config = config;
    this.logger = new Logger();
    this.ansiFilter = new AnsiFilter(config.sanitization?.ansi_escapes || {});
    this.charWhitelist = new CharacterWhitelist(config.sanitization?.character_whitelist || {});
    this.patternMatcher = new PatternMatcher(config.sanitization?.patterns || {});
  }
  
  sanitizeMessage(message: any): { safe: boolean; modified: boolean; message: any; violations: string[]; modifications?: string[] } {
    const violations: string[] = [];
    const modifications: string[] = [];
    let modified = false;
    
    const sanitizedMessage = this.deepSanitize(message, violations, modifications);
    
    if (modifications.length > 0) {
      modified = true;
    }
    
    return {
      safe: violations.length === 0 || !(this.config.sanitization as any)?.strict_mode,
      modified,
      message: sanitizedMessage,
      violations,
      modifications
    };
  }
  
  private deepSanitize(obj: any, violations: string[], modifications: string[]): any {
    if (typeof obj === 'string') {
      const ansiResult = this.ansiFilter.filter(obj);
      if (ansiResult.violations.length > 0) {
        violations.push(...ansiResult.violations);
        modifications.push('ansi_removed');
      }
      
      const charResult = this.charWhitelist.filter(ansiResult.filtered);
      if (charResult.violations.length > 0) {
        violations.push(...charResult.violations);
        modifications.push('chars_filtered');
      }
      
      const patternResult = this.patternMatcher.match(charResult.filtered);
      if (patternResult.matched) {
        violations.push(...patternResult.violations);
      }
      
      return charResult.filtered;
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => this.deepSanitize(item, violations, modifications));
    }
    
    if (typeof obj === 'object' && obj !== null) {
      const result: any = {};
      for (const [key, value] of Object.entries(obj)) {
        result[key] = this.deepSanitize(value, violations, modifications);
      }
      return result;
    }
    
    return obj;
  }

  sanitize(input: string, context: string = 'unknown'): SanitizationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const originalLength = input.length;
    let sanitized = input;

    const stats = {
      originalLength,
      sanitizedLength: 0,
      charactersRemoved: 0,
      patternsDetected: 0,
      ansiSequencesRemoved: false
    };

    try {
      if (this.exceedsMaxLength(sanitized, context)) {
        errors.push(`Input exceeds maximum length for ${context}`);
        return this.createResult(false, null, errors, warnings, stats);
      }

      const ansiResult = this.ansiFilter.filter(sanitized);
      const ansiFiltered = ansiResult.filtered;
      if (!ansiFiltered) {
        errors.push('Input rejected due to ANSI escape sequences');
        return this.createResult(false, null, errors, warnings, stats);
      }
      
      if (ansiFiltered !== sanitized) {
        stats.ansiSequencesRemoved = true;
        warnings.push('ANSI escape sequences were removed');
      }
      sanitized = ansiFiltered;

      const charResult = this.charWhitelist.filter(sanitized);
      const charFiltered = charResult.filtered;
      if (!charFiltered && charFiltered !== '') {
        errors.push('Input rejected due to invalid characters');
        return this.createResult(false, null, errors, warnings, stats);
      }
      
      if (charFiltered.length !== sanitized.length) {
        stats.charactersRemoved += sanitized.length - charFiltered.length;
        warnings.push(`${stats.charactersRemoved} characters were filtered`);
      }
      sanitized = charFiltered;

      const patternResult = this.patternMatcher.check(sanitized, context);
      if (!patternResult.allowed) {
        errors.push('Input rejected due to dangerous patterns');
        stats.patternsDetected = patternResult.matches.length;
        return this.createResult(false, null, errors, warnings, stats);
      }
      
      if (patternResult.matches.length > 0) {
        stats.patternsDetected = patternResult.matches.length;
        for (const match of patternResult.matches) {
          warnings.push(`Pattern detected: ${match.pattern.name} (${match.pattern.severity})`);
        }
      }
      sanitized = patternResult.sanitized;

      sanitized = this.performFieldSpecificSanitization(sanitized, context);

      stats.sanitizedLength = sanitized.length;
      stats.charactersRemoved = originalLength - sanitized.length;

      if (stats.charactersRemoved > 0 || stats.patternsDetected > 0 || stats.ansiSequencesRemoved) {
        this.logger.info('Input sanitized', {
          context,
          stats,
          warnings
        });
      }

      return this.createResult(true, sanitized, errors, warnings, stats);

    } catch (error) {
      this.logger.error('Sanitization error', { error, context });
      errors.push(`Sanitization failed: ${error}`);
      return this.createResult(false, null, errors, warnings, stats);
    }
  }

  private exceedsMaxLength(input: string, context: string): boolean {
    const limits = this.config.sanitization.validation;
    
    switch (context) {
      case 'prompt':
      case 'prompts':
        return input.length > limits.max_prompt_length;
      
      case 'tool_name':
        return input.length > limits.max_tool_name_length;
      
      case 'tool_params':
      case 'tool_parameters':
        return input.length > limits.max_param_value_length;
      
      default:
        const maxSize = this.parseSize(limits.max_message_size);
        return Buffer.byteLength(input, 'utf8') > maxSize;
    }
  }

  private parseSize(sizeStr: string): number {
    const match = sizeStr.match(/^(\d+)(MB|KB|B)?$/i);
    if (!match) return 1024 * 1024;
    
    const value = parseInt(match[1]!, 10);
    const unit = match[2]?.toUpperCase() || 'B';
    
    switch (unit) {
      case 'MB': return value * 1024 * 1024;
      case 'KB': return value * 1024;
      case 'B': return value;
      default: return value;
    }
  }

  private performFieldSpecificSanitization(input: string, context: string): string {
    const fieldConfig = this.config.sanitization.validation.fields;
    
    switch (context) {
      case 'tool_name':
        const pattern = new RegExp(fieldConfig.tool_name.pattern);
        if (!pattern.test(input)) {
          return input.replace(/[^a-zA-Z0-9_-]/g, '');
        }
        return input;
      
      case 'tool_params':
      case 'tool_parameters':
        let result = input;
        if (fieldConfig.tool_params.strip_html) {
          result = this.stripHtml(result);
        }
        if (fieldConfig.tool_params.strip_scripts) {
          result = this.stripScripts(result);
        }
        return result;
      
      default:
        return input;
    }
  }

  private stripHtml(input: string): string {
    return input.replace(/<[^>]*>/g, '');
  }

  private stripScripts(input: string): string {
    return input
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/on\w+\s*=\s*"[^"]*"/gi, '')
      .replace(/on\w+\s*=\s*'[^']*'/gi, '')
      .replace(/javascript:/gi, '');
  }

  private createResult(
    success: boolean,
    sanitized: string | null,
    errors: string[],
    warnings: string[],
    stats: any
  ): SanitizationResult {
    return {
      success,
      sanitized,
      errors,
      warnings,
      stats
    };
  }

  public sanitizeJsonRpc(message: any): SanitizationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    
    try {
      if (typeof message !== 'object' || message === null) {
        errors.push('Invalid JSON-RPC message structure');
        return this.createResult(false, null, errors, warnings, {
          originalLength: 0,
          sanitizedLength: 0,
          charactersRemoved: 0,
          patternsDetected: 0,
          ansiSequencesRemoved: false
        });
      }

      const sanitizedMessage = { ...message };

      if (message.method && typeof message.method === 'string') {
        const methodResult = this.sanitize(message.method, 'tool_name');
        if (!methodResult.success) {
          return methodResult;
        }
        sanitizedMessage.method = methodResult.sanitized;
        warnings.push(...methodResult.warnings);
      }

      if (message.params) {
        sanitizedMessage.params = this.sanitizeObject(message.params, 'tool_params');
      }

      if (message.result) {
        sanitizedMessage.result = this.sanitizeObject(message.result, 'response');
      }

      if (message.error && message.error.message) {
        const errorResult = this.sanitize(message.error.message, 'error_message');
        if (errorResult.success && errorResult.sanitized) {
          sanitizedMessage.error.message = errorResult.sanitized;
        }
      }

      return this.createResult(true, JSON.stringify(sanitizedMessage), errors, warnings, {
        originalLength: JSON.stringify(message).length,
        sanitizedLength: JSON.stringify(sanitizedMessage).length,
        charactersRemoved: 0,
        patternsDetected: 0,
        ansiSequencesRemoved: false
      });

    } catch (error) {
      this.logger.error('JSON-RPC sanitization error', { error });
      errors.push(`JSON-RPC sanitization failed: ${error}`);
      return this.createResult(false, null, errors, warnings, {
        originalLength: 0,
        sanitizedLength: 0,
        charactersRemoved: 0,
        patternsDetected: 0,
        ansiSequencesRemoved: false
      });
    }
  }

  private sanitizeObject(obj: any, context: string): any {
    if (typeof obj === 'string') {
      const result = this.sanitize(obj, context);
      return result.success ? result.sanitized : obj;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item, context));
    }

    if (typeof obj === 'object' && obj !== null) {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(obj)) {
        const sanitizedKey = this.sanitize(key, 'object_key');
        if (sanitizedKey.success && sanitizedKey.sanitized) {
          sanitized[sanitizedKey.sanitized] = this.sanitizeObject(value, context);
        }
      }
      return sanitized;
    }

    return obj;
  }
}