import WebSocket from 'ws';
import { EventEmitter } from 'events';
import { Logger } from '../monitoring/logger';
import { MCPMessage } from './client_handler';
import { Sanitizer } from '../security/sanitizer';

export class ServerHandler extends EventEmitter {
  private serverWs?: WebSocket;
  private serverUrl: string;
  private connectionId: string;
  private config: any;
  private logger: Logger;
  private sanitizer?: Sanitizer;
  private connected = false;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private messageQueue: MCPMessage[] = [];
  private isClosing = false;

  constructor(
    connectionId: string,
    serverUrl: string,
    config: any,
    logger: Logger
  ) {
    super();
    this.connectionId = connectionId;
    this.serverUrl = serverUrl;
    this.config = config;
    this.logger = logger;
    
    // Initialize sanitizer if API key protection is enabled
    if (config.api_key_protection?.enabled) {
      this.sanitizer = new Sanitizer(config, connectionId);
    }
  }

  public connect(): void {
    if (this.isClosing) return;

    try {
      this.logger.info('Connecting to MCP server', {
        connectionId: this.connectionId,
        serverUrl: this.serverUrl
      });

      this.serverWs = new WebSocket(this.serverUrl, {
        handshakeTimeout: this.config.proxy?.connection_timeout || 10000,
        maxPayload: this.config.proxy?.max_message_size || 10 * 1024 * 1024 // 10MB default
      });

      this.setupServerHandlers();
    } catch (error) {
      this.logger.error('Failed to create MCP server connection', {
        connectionId: this.connectionId,
        error: (error as Error).message
      });
      this.handleReconnect();
    }
  }

  private setupServerHandlers(): void {
    if (!this.serverWs) return;

    this.serverWs.on('open', this.handleServerOpen.bind(this));
    this.serverWs.on('message', this.handleServerMessage.bind(this));
    this.serverWs.on('close', this.handleServerClose.bind(this));
    this.serverWs.on('error', this.handleServerError.bind(this));
    this.serverWs.on('ping', () => {
      if (this.serverWs && this.serverWs.readyState === WebSocket.OPEN) {
        this.serverWs.pong();
      }
    });
  }

  private handleServerOpen(): void {
    this.connected = true;
    this.reconnectAttempts = 0;
    
    this.logger.info('Connected to MCP server', {
      connectionId: this.connectionId,
      serverUrl: this.serverUrl
    });

    // Send any queued messages
    this.flushMessageQueue();
  }

  private handleServerMessage(data: WebSocket.Data): void {
    try {
      const rawMessage = data.toString();
      const message: MCPMessage = JSON.parse(rawMessage);

      this.logger.debug('Received message from MCP server', {
        connectionId: this.connectionId,
        method: message.method,
        hasResult: !!message.result,
        hasError: !!message.error
      });

      // Validate the response
      if (!this.validateServerMessage(message)) {
        this.logger.warn('Invalid message from MCP server', {
          connectionId: this.connectionId,
          message
        });
        return;
      }

      // Emit the message to be forwarded to client
      this.emit('message', message);

    } catch (error) {
      this.logger.error('Error parsing MCP server message', {
        connectionId: this.connectionId,
        error: (error as Error).message
      });
    }
  }

  private validateServerMessage(message: MCPMessage): boolean {
    // Basic JSON-RPC validation
    if (message.jsonrpc !== '2.0') {
      return false;
    }

    // Server can send notifications (method without id) or responses
    if (message.method) {
      // Notification or request from server
      return typeof message.method === 'string';
    } else {
      // Response must have result or error
      return message.result !== undefined || message.error !== undefined;
    }
  }

  private handleServerClose(code: number, reason: Buffer): void {
    this.connected = false;
    
    this.logger.info('MCP server connection closed', {
      connectionId: this.connectionId,
      code,
      reason: reason.toString()
    });

    if (!this.isClosing && this.config.proxy?.auto_reconnect) {
      this.handleReconnect();
    } else {
      this.emit('close');
    }
  }

  private handleServerError(error: Error): void {
    this.logger.error('MCP server WebSocket error', {
      connectionId: this.connectionId,
      error: error.message
    });

    this.emit('error', error);
  }

  private handleReconnect(): void {
    if (this.isClosing) return;
    
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.logger.error('Max reconnection attempts reached', {
        connectionId: this.connectionId,
        attempts: this.reconnectAttempts
      });
      this.emit('close');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    this.logger.info('Scheduling reconnection to MCP server', {
      connectionId: this.connectionId,
      attempt: this.reconnectAttempts,
      delayMs: delay
    });

    setTimeout(() => {
      if (!this.isClosing) {
        this.connect();
      }
    }, delay);
  }

  private flushMessageQueue(): void {
    if (!this.connected || !this.serverWs) return;

    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift();
      if (message) {
        this.sendToServer(message);
      }
    }
  }

  public sendToServer(message: MCPMessage): void {
    if (!this.serverWs) {
      this.logger.error('No MCP server WebSocket connection', {
        connectionId: this.connectionId
      });
      return;
    }

    // Re-substitute API keys before sending to MCP server
    let messageToSend = message;
    if (this.sanitizer && this.config.api_key_protection?.enabled) {
      const resubstitutionResult = this.sanitizer.resubstituteApiKeys(message);
      if (resubstitutionResult.modified) {
        this.logger.debug('API keys re-substituted for MCP server', {
          connectionId: this.connectionId,
          method: message.method
        });
        messageToSend = resubstitutionResult.message;
      }
    }

    // Queue message if not connected
    if (!this.connected) {
      if (this.messageQueue.length < (this.config.proxy?.max_queue_size || 100)) {
        this.messageQueue.push(messageToSend);
        this.logger.debug('Message queued for MCP server', {
          connectionId: this.connectionId,
          queueSize: this.messageQueue.length
        });
      } else {
        this.logger.warn('Message queue full, dropping message', {
          connectionId: this.connectionId,
          method: messageToSend.method
        });
      }
      return;
    }

    try {
      if (this.serverWs.readyState === WebSocket.OPEN) {
        this.serverWs.send(JSON.stringify(messageToSend));
        
        this.logger.debug('Message sent to MCP server', {
          connectionId: this.connectionId,
          method: messageToSend.method,
          hasParams: !!messageToSend.params
        });
      } else {
        this.logger.warn('MCP server WebSocket not open', {
          connectionId: this.connectionId,
          readyState: this.serverWs.readyState
        });
        
        // Try to queue for later
        if (this.messageQueue.length < (this.config.proxy?.max_queue_size || 100)) {
          this.messageQueue.push(messageToSend);
        }
      }
    } catch (error) {
      this.logger.error('Failed to send message to MCP server', {
        connectionId: this.connectionId,
        error: (error as Error).message
      });
    }
  }

  public isConnected(): boolean {
    return this.connected && this.serverWs?.readyState === WebSocket.OPEN;
  }

  public close(): void {
    if (this.isClosing) return;
    this.isClosing = true;

    this.logger.info('Closing MCP server connection', {
      connectionId: this.connectionId
    });

    if (this.serverWs) {
      if (this.serverWs.readyState === WebSocket.OPEN) {
        this.serverWs.close();
      }
      this.serverWs = undefined;
    }

    this.connected = false;
    this.messageQueue = [];
  }
}