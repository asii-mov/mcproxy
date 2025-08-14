export interface AnsiFilterConfig {
  enabled?: boolean;
  action?: 'strip' | 'reject' | 'encode';
}

export interface FilterResult {
  filtered: string;
  violations: string[];
}

export class AnsiFilter {
  private config: AnsiFilterConfig;

  constructor(config: AnsiFilterConfig) {
    this.config = config;
  }

  filter(input: string): FilterResult {
    if (!this.config.enabled) {
      return { filtered: input, violations: [] };
    }

    const hasAnsi = this.detectAnsi(input);
    
    if (!hasAnsi) {
      return { filtered: input, violations: [] };
    }

    const action = this.config.action || 'strip';
    
    switch (action) {
      case 'strip':
        return {
          filtered: this.stripAnsi(input),
          violations: ['ansi_sequences_removed']
        };
      
      case 'reject':
        return {
          filtered: '',
          violations: ['ansi_sequences_rejected']
        };
      
      case 'encode':
        return {
          filtered: this.encodeAnsi(input),
          violations: ['ansi_sequences_encoded']
        };
      
      default:
        return { filtered: input, violations: [] };
    }
  }

  private detectAnsi(input: string): boolean {
    // Check for various ANSI escape sequence patterns
    const ansiPatterns = [
      /\x1b\[/,        // Standard ANSI escape
      /\u001b\[/,      // Unicode escape
      /\\x1b\[/,       // Escaped hex
      /\\u001b\[/      // Escaped unicode
    ];

    return ansiPatterns.some(pattern => pattern.test(input));
  }

  private stripAnsi(input: string): string {
    // Remove all ANSI escape sequences
    const patterns = [
      /\x1b\[[0-9;]*[A-Za-z]/g,           // CSI sequences
      /\x1b\][^\x07]*\x07/g,              // OSC sequences
      /\x1b[PX^_].*?\x1b\\/g,             // DCS/PM/APC/SOS sequences
      /\x1b\[[0-9;]*m/g,                  // SGR sequences (colors/styles)
      /\x1b\(B/g,                         // Character set sequences
      /\x1b\)0/g,
      /\x1b[>=]/g,                        // Other escape sequences
      /\x1b\[[?][0-9;]*[hl]/g,            // DEC private mode
      /\x1b\[=[0-9;]*[hl]/g,              // Screen mode
      /\x9b[0-9;]*[A-Za-z]/g,             // 8-bit CSI
      /\x1b[78]/g,                        // Save/restore cursor
      /\x1b\[[0-9;]*[HfABCDsuJKmGT]/g     // Various cursor/screen commands
    ];

    let result = input;
    for (const pattern of patterns) {
      result = result.replace(pattern, '');
    }

    // Remove any remaining ESC characters
    result = result.replace(/\x1b/g, '');
    result = result.replace(/\u001b/g, '');

    return result;
  }

  private encodeAnsi(input: string): string {
    // Encode ANSI escape sequences as visible strings
    return input
      .replace(/\x1b/g, '\\x1b')
      .replace(/\u001b/g, '\\u001b');
  }

  public static removeAllControlCharacters(input: string): string {
    // Remove all control characters except newline, carriage return, and tab
    return input.replace(/[\x00-\x1F\x7F-\x9F]/g, (match) => {
      if (match === '\n' || match === '\r' || match === '\t') {
        return match;
      }
      return '';
    });
  }
}