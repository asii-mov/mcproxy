import winston from 'winston';

export class Logger {
  private logger: winston.Logger;

  constructor() {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        })
      ]
    });
  }

  info(message: string, meta?: any): void {
    this.logger.info(message, meta);
  }

  warn(message: string, meta?: any): void {
    this.logger.warn(message, meta);
  }

  error(message: string, meta?: any): void {
    this.logger.error(message, meta);
  }

  debug(message: string, meta?: any): void {
    this.logger.debug(message, meta);
  }

  security(message: string, meta?: any): void {
    this.logger.warn(`[SECURITY] ${message}`, meta);
  }

  audit(message: string, meta?: any): void {
    this.logger.info(`[AUDIT] ${message}`, meta);
  }
}