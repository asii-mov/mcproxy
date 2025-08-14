import WebSocket from 'ws';
import { createServer, Server as HttpServer } from 'http';
import { EventEmitter } from 'events';
import { loadConfig } from '../config/loader';
import { Logger } from '../monitoring/logger';
import { ClientHandler } from './client_handler';

export interface ProxyConfig {
  port: number;
  host: string;
  mcpServerUrl: string;
  maxConnections?: number;
}

export class MCPProxyServer extends EventEmitter {
  private httpServer: HttpServer;
  private wsServer: WebSocket.Server;
  private logger: Logger;
  private config: any;
  private connections: Map<string, ClientHandler> = new Map();
  private connectionCounter = 0;

  constructor(config?: Partial<ProxyConfig>) {
    super();
    this.logger = new Logger();
    this.config = loadConfig();
    
    const proxyConfig = {
      port: config?.port || this.config.proxy?.port || 8080,
      host: config?.host || this.config.proxy?.host || '0.0.0.0',
      mcpServerUrl: config?.mcpServerUrl || this.config.proxy?.mcp_server_url || 'ws://localhost:3000',
      maxConnections: config?.maxConnections || this.config.proxy?.max_connections || 100
    };

    this.httpServer = createServer();
    this.wsServer = new WebSocket.Server({ server: this.httpServer });

    this.setupEventHandlers();
    
    this.logger.info('MCP Security Proxy initialized', {
      port: proxyConfig.port,
      host: proxyConfig.host,
      mcpServer: proxyConfig.mcpServerUrl
    });
  }

  private setupEventHandlers(): void {
    this.wsServer.on('connection', this.handleConnection.bind(this));
    this.wsServer.on('error', (error) => {
      this.logger.error('WebSocket server error', { error: error.message });
    });
  }

  private handleConnection(clientWs: WebSocket, request: any): void {
    const connectionId = `conn-${++this.connectionCounter}`;
    const clientIp = request.socket.remoteAddress;

    if (this.connections.size >= (this.config.proxy?.max_connections || 100)) {
      this.logger.warn('Max connections reached, rejecting new connection', {
        connectionId,
        clientIp,
        currentConnections: this.connections.size
      });
      clientWs.close(1008, 'Max connections reached');
      return;
    }

    this.logger.info('New client connection', {
      connectionId,
      clientIp,
      totalConnections: this.connections.size + 1
    });

    const clientHandler = new ClientHandler(
      connectionId,
      clientWs,
      this.config,
      this.logger
    );

    this.connections.set(connectionId, clientHandler);

    clientHandler.on('close', () => {
      this.connections.delete(connectionId);
      this.logger.info('Client disconnected', {
        connectionId,
        remainingConnections: this.connections.size
      });
    });

    clientHandler.on('security-event', (event) => {
      this.logger.security('Security event detected', {
        connectionId,
        ...event
      });
      this.emit('security-event', { connectionId, ...event });
    });

    clientHandler.connect(this.config.proxy?.mcp_server_url || 'ws://localhost:3000');
  }

  public start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const port = this.config.proxy?.port || 8080;
      const host = this.config.proxy?.host || '0.0.0.0';

      this.httpServer.listen(port, host, () => {
        this.logger.info('MCP Security Proxy started', {
          port,
          host,
          url: `ws://${host}:${port}`
        });
        resolve();
      });

      this.httpServer.on('error', (error) => {
        this.logger.error('HTTP server error', { error: error.message });
        reject(error);
      });
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      this.logger.info('Shutting down MCP Security Proxy...');

      // Close all client connections
      for (const [, handler] of this.connections) {
        handler.close();
      }
      this.connections.clear();

      // Close WebSocket server
      this.wsServer.close(() => {
        this.logger.info('WebSocket server closed');
      });

      // Close HTTP server
      this.httpServer.close(() => {
        this.logger.info('HTTP server closed');
        resolve();
      });
    });
  }

  public getStats() {
    return {
      activeConnections: this.connections.size,
      totalConnectionsHandled: this.connectionCounter,
      uptime: process.uptime()
    };
  }
}