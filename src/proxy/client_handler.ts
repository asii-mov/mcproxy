import WebSocket from 'ws';
import { EventEmitter } from 'events';
import { Logger } from '../monitoring/logger';
import { Sanitizer } from '../security/sanitizer';
import { ServerHandler } from './server_handler';
import { RateLimiter } from '../security/ratelimit';

export interface MCPMessage {
  jsonrpc: string;
  method?: string;
  params?: any;
  result?: any;
  error?: any;
  id?: string | number;
}

export class ClientHandler extends EventEmitter {
  private clientWs: WebSocket;
  private serverHandler?: ServerHandler;
  private sanitizer: Sanitizer;
  private rateLimiter?: RateLimiter;
  private logger: Logger;
  private connectionId: string;
  private config: any;
  private messageCounter = 0;
  private isClosing = false;

  constructor(
    connectionId: string,
    clientWs: WebSocket,
    config: any,
    logger: Logger
  ) {
    super();
    this.connectionId = connectionId;
    this.clientWs = clientWs;
    this.config = config;
    this.logger = logger;
    this.sanitizer = new Sanitizer(config);

    if (config.rate_limiting?.enabled) {
      this.rateLimiter = new RateLimiter(config.rate_limiting);
    }

    this.setupClientHandlers();
  }

  private setupClientHandlers(): void {
    this.clientWs.on('message', this.handleClientMessage.bind(this));
    this.clientWs.on('close', this.handleClientClose.bind(this));
    this.clientWs.on('error', this.handleClientError.bind(this));
    this.clientWs.on('ping', () => this.clientWs.pong());
  }

  private async handleClientMessage(data: WebSocket.Data): Promise<void> {
    this.messageCounter++;
    const messageId = `${this.connectionId}-msg-${this.messageCounter}`;

    try {
      // Parse message
      const rawMessage = data.toString();
      let message: MCPMessage;

      try {
        message = JSON.parse(rawMessage);
      } catch (error) {
        this.logger.warn('Invalid JSON from client', {
          connectionId: this.connectionId,
          messageId,
          error: (error as Error).message
        });
        this.sendError(null, 'Invalid JSON format');
        return;
      }

      // Validate JSON-RPC structure
      if (!this.validateJsonRpc(message)) {
        this.logger.warn('Invalid JSON-RPC message', {
          connectionId: this.connectionId,
          messageId,
          message
        });
        this.sendError(message.id, 'Invalid JSON-RPC message');
        return;
      }

      // Apply rate limiting
      if (this.rateLimiter) {
        const allowed = await this.rateLimiter.checkLimit(this.connectionId, message.method);
        if (!allowed) {
          this.logger.warn('Rate limit exceeded', {
            connectionId: this.connectionId,
            messageId,
            method: message.method
          });
          this.sendError(message.id, 'Rate limit exceeded');
          this.emit('security-event', {
            type: 'rate_limit_exceeded',
            method: message.method,
            messageId
          });
          return;
        }
      }

      // Sanitize message content
      const sanitizationResult = this.sanitizer.sanitizeMessage(message);
      
      if (!sanitizationResult.safe) {
        this.logger.warn('Message blocked by sanitization', {
          connectionId: this.connectionId,
          messageId,
          violations: sanitizationResult.violations,
          method: message.method
        });
        
        this.emit('security-event', {
          type: 'sanitization_blocked',
          violations: sanitizationResult.violations,
          method: message.method,
          messageId
        });

        if (this.config.sanitization?.strict_mode) {
          this.sendError(message.id, 'Message contains forbidden content');
          return;
        }
      }

      // Log sanitized content if modified
      if (sanitizationResult.modified) {
        this.logger.info('Message sanitized', {
          connectionId: this.connectionId,
          messageId,
          modifications: sanitizationResult.modifications
        });
      }

      // Forward to MCP server
      if (this.serverHandler && this.serverHandler.isConnected()) {
        this.serverHandler.sendToServer(sanitizationResult.message);
        
        this.logger.debug('Message forwarded to MCP server', {
          connectionId: this.connectionId,
          messageId,
          method: message.method
        });
      } else {
        this.logger.error('No active MCP server connection', {
          connectionId: this.connectionId,
          messageId
        });
        this.sendError(message.id, 'MCP server not connected');
      }

    } catch (error) {
      this.logger.error('Error handling client message', {
        connectionId: this.connectionId,
        messageId,
        error: (error as Error).message
      });
      this.sendError(null, 'Internal proxy error');
    }
  }

  private validateJsonRpc(message: MCPMessage): boolean {
    // Check for required JSON-RPC fields
    if (message.jsonrpc !== '2.0') {
      return false;
    }

    // Request must have method
    if (message.method && typeof message.method !== 'string') {
      return false;
    }

    // Response must have result or error
    if (!message.method && !message.result && !message.error) {
      return false;
    }

    return true;
  }

  private sendError(id: any, message: string): void {
    const errorResponse: MCPMessage = {
      jsonrpc: '2.0',
      error: {
        code: -32603,
        message: message
      },
      id: id || null
    };

    this.sendToClient(errorResponse);
  }

  public sendToClient(message: MCPMessage): void {
    if (this.clientWs.readyState === WebSocket.OPEN) {
      try {
        this.clientWs.send(JSON.stringify(message));
      } catch (error) {
        this.logger.error('Failed to send message to client', {
          connectionId: this.connectionId,
          error: (error as Error).message
        });
      }
    }
  }

  public connect(mcpServerUrl: string): void {
    this.serverHandler = new ServerHandler(
      this.connectionId,
      mcpServerUrl,
      this.config,
      this.logger
    );

    this.serverHandler.on('message', (message: MCPMessage) => {
      // Apply sanitization to responses from MCP server
      const sanitizationResult = this.sanitizer.sanitizeMessage(message);
      
      if (sanitizationResult.modified) {
        this.logger.info('Server response sanitized', {
          connectionId: this.connectionId,
          modifications: sanitizationResult.modifications
        });
      }

      this.sendToClient(sanitizationResult.message);
    });

    this.serverHandler.on('close', () => {
      if (!this.isClosing) {
        this.logger.info('MCP server connection closed', {
          connectionId: this.connectionId
        });
        this.close();
      }
    });

    this.serverHandler.on('error', (error) => {
      this.logger.error('MCP server error', {
        connectionId: this.connectionId,
        error: error.message
      });
    });

    this.serverHandler.connect();
  }

  private handleClientClose(): void {
    if (!this.isClosing) {
      this.isClosing = true;
      this.logger.info('Client connection closed', {
        connectionId: this.connectionId,
        messagesProcessed: this.messageCounter
      });
      this.close();
    }
  }

  private handleClientError(error: Error): void {
    this.logger.error('Client WebSocket error', {
      connectionId: this.connectionId,
      error: error.message
    });
  }

  public close(): void {
    if (this.isClosing) return;
    this.isClosing = true;

    if (this.serverHandler) {
      this.serverHandler.close();
    }

    if (this.clientWs.readyState === WebSocket.OPEN) {
      this.clientWs.close();
    }

    this.emit('close');
  }
}