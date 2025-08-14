export interface CharWhitelistConfig {
  enabled?: boolean;
  allowed_ranges?: number[][];
  blacklist?: number[];
}

export interface FilterResult {
  filtered: string;
  violations: string[];
}

export class CharacterWhitelist {
  private config: CharWhitelistConfig;
  private allowedChars: Set<number>;

  constructor(config: CharWhitelistConfig) {
    this.config = config;
    this.allowedChars = this.buildAllowedSet();
  }

  private buildAllowedSet(): Set<number> {
    const allowed = new Set<number>();
    
    // Default to printable ASCII if no ranges specified
    const ranges = this.config.allowed_ranges || [[0x20, 0x7E]];
    
    for (const range of ranges) {
      if (range.length === 2) {
        const [start, end] = range;
        if (start !== undefined && end !== undefined) {
          for (let i = start; i <= end; i++) {
            allowed.add(i);
          }
        }
      }
    }
    
    // Remove blacklisted characters
    const blacklist = this.config.blacklist || [0x1B, 0x7F];
    for (const char of blacklist) {
      allowed.delete(char);
    }
    
    return allowed;
  }

  filter(input: string): FilterResult {
    if (!this.config.enabled) {
      return { filtered: input, violations: [] };
    }

    const violations: string[] = [];
    let filtered = '';
    let removed = false;
    
    for (let i = 0; i < input.length; i++) {
      const charCode = input.charCodeAt(i);
      
      if (this.allowedChars.has(charCode)) {
        filtered += input[i];
      } else {
        removed = true;
        
        // Check for specific problematic characters
        if (this.isZeroWidthChar(charCode)) {
          if (!violations.includes('zero_width_chars_removed')) {
            violations.push('zero_width_chars_removed');
          }
        } else if (this.isControlChar(charCode)) {
          if (!violations.includes('control_chars_removed')) {
            violations.push('control_chars_removed');
          }
        } else if (charCode > 0x7E) {
          if (!violations.includes('unicode_chars_removed')) {
            violations.push('unicode_chars_removed');
          }
        }
      }
    }
    
    if (removed && !violations.includes('non_whitelisted_chars_removed')) {
      violations.push('non_whitelisted_chars_removed');
    }
    
    return { filtered, violations };
  }

  private isZeroWidthChar(charCode: number): boolean {
    // Common zero-width and invisible characters
    const zeroWidthChars = [
      0x200B, // Zero-width space
      0x200C, // Zero-width non-joiner
      0x200D, // Zero-width joiner
      0xFEFF, // Zero-width no-break space
      0x2060, // Word joiner
      0x180E, // Mongolian vowel separator
      0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 
      0x2006, 0x2007, 0x2008, 0x2009, 0x200A  // Various spaces
    ];
    
    return zeroWidthChars.includes(charCode);
  }

  private isControlChar(charCode: number): boolean {
    // Control characters (0x00-0x1F and 0x7F-0x9F)
    // Excluding common allowed ones like \n, \r, \t
    if (charCode === 0x09 || charCode === 0x0A || charCode === 0x0D) {
      return false; // Allow tab, newline, carriage return
    }
    
    return (charCode >= 0x00 && charCode <= 0x1F) || 
           (charCode >= 0x7F && charCode <= 0x9F);
  }

  public static normalizeUnicode(input: string): string {
    // Normalize to NFC (Canonical Decomposition, followed by Canonical Composition)
    if (typeof input.normalize === 'function') {
      return input.normalize('NFC');
    }
    return input;
  }

  public static detectHomoglyphs(input: string): boolean {
    // Common homoglyph patterns
    const homoglyphPatterns = [
      /[\u0430\u043e\u0435\u0440\u0441\u0443\u0445]/i, // Cyrillic look-alikes
      /[\u03bf\u03c1]/i, // Greek look-alikes
      /[\u2010-\u2015]/,  // Various dashes that look like hyphens
      /[\u1680\u2000-\u200a\u202f\u205f\u3000]/ // Various spaces
    ];
    
    return homoglyphPatterns.some(pattern => pattern.test(input));
  }
}