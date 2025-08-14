export interface PatternConfig {
  enabled?: boolean;
  rules?: Array<{
    name: string;
    pattern: string;
    action?: string;
  }>;
}

export interface MatchResult {
  matched: boolean;
  violations: string[];
}

export class PatternMatcher {
  private config: PatternConfig;
  private patterns: Array<{ name: string; regex: RegExp; action: string }>;

  constructor(config: PatternConfig) {
    this.config = config;
    this.patterns = this.compilePatterns();
  }

  private compilePatterns(): Array<{ name: string; regex: RegExp; action: string }> {
    if (!this.config.rules) {
      return [];
    }

    return this.config.rules.map(rule => ({
      name: rule.name,
      regex: new RegExp(rule.pattern, 'gi'),
      action: rule.action || 'reject'
    }));
  }

  match(input: string): MatchResult {
    if (!this.config.enabled) {
      return { matched: false, violations: [] };
    }

    const violations: string[] = [];
    
    for (const pattern of this.patterns) {
      if (pattern.regex.test(input)) {
        violations.push(pattern.name);
      }
    }
    
    return {
      matched: violations.length > 0,
      violations
    };
  }

  check(input: string, context?: string): { allowed: boolean; matches: any[]; sanitized: string } {
    const matches: any[] = [];
    let sanitized = input;
    
    for (const pattern of this.patterns) {
      if (pattern.regex.test(input)) {
        matches.push({
          pattern: {
            name: pattern.name,
            severity: 'high'
          },
          context
        });
        
        if (pattern.action === 'strip') {
          sanitized = sanitized.replace(pattern.regex, '');
        }
      }
    }
    
    return {
      allowed: matches.length === 0,
      matches,
      sanitized
    };
  }

  public static getDefaultPatterns(): PatternConfig {
    return {
      enabled: true,
      rules: [
        {
          name: 'command_injection',
          pattern: '[;&|`$(){}\\[\\]<>]',
          action: 'reject'
        },
        {
          name: 'path_traversal',
          pattern: '\\.\\./|\\.\\.\\\\'
        },
        {
          name: 'prompt_injection',
          pattern: '(ignore previous|system:|assistant:|forget everything)',
          action: 'reject'
        },
        {
          name: 'sql_injection',
          pattern: '(\\bUNION\\b|\\bSELECT\\b.*\\bFROM\\b|\\bDROP\\b|\\bINSERT\\b|\\bUPDATE\\b|\\bDELETE\\b)',
          action: 'reject'
        }
      ]
    };
  }
}