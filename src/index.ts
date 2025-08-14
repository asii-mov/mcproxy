#!/usr/bin/env node

import { MCPProxyServer } from './proxy/server';
import { Logger } from './monitoring/logger';
import { loadConfig } from './config/loader';
import * as fs from 'fs';
import * as path from 'path';
import { Command } from 'commander';

const logger = new Logger();

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled rejection', { reason, promise });
  process.exit(1);
});

// CLI setup
const program = new Command();
program
  .name('mcproxy')
  .description('MCP Security Proxy - Secure gateway for Model Context Protocol')
  .version('1.0.0')
  .option('-c, --config <path>', 'Path to configuration file', 'mcproxy-config.yaml')
  .option('-p, --port <number>', 'Port to listen on', '8080')
  .option('-h, --host <address>', 'Host to bind to', '0.0.0.0')
  .option('-s, --server <url>', 'MCP server URL', 'ws://localhost:3000')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--strict', 'Enable strict mode (reject all unsafe content)')
  .parse(process.argv);

const options = program.opts();

async function main() {
  try {
    // Load configuration
    let configPath = options.config;
    if (!path.isAbsolute(configPath)) {
      configPath = path.join(process.cwd(), configPath);
    }

    if (!fs.existsSync(configPath)) {
      logger.warn(`Configuration file not found at ${configPath}, using defaults`);
    }

    const config = loadConfig(configPath);

    // Override config with CLI options
    if (options.port) {
      config.proxy = config.proxy || {};
      config.proxy.port = parseInt(options.port);
    }
    if (options.host) {
      config.proxy = config.proxy || {};
      config.proxy.host = options.host;
    }
    if (options.server) {
      config.proxy = config.proxy || {};
      config.proxy.mcp_server_url = options.server;
    }
    if (options.strict) {
      config.sanitization = config.sanitization || {};
      config.sanitization.strict_mode = true;
    }
    if (options.verbose) {
      config.logging = config.logging || {};
      config.logging.level = 'debug';
    }

    // Display startup banner
    console.log(`
╔══════════════════════════════════════════╗
║       MCP Security Proxy v1.0.0          ║
║   Protecting against injection attacks   ║
╚══════════════════════════════════════════╝
`);

    logger.info('Starting MCP Security Proxy', {
      config: {
        port: config.proxy?.port || 8080,
        host: config.proxy?.host || '0.0.0.0',
        mcpServer: config.proxy?.mcp_server_url || 'ws://localhost:3000',
        strictMode: config.sanitization?.strict_mode || false,
        rateLimiting: config.rate_limiting?.enabled || false
      }
    });

    // Display security features status
    console.log('Security Features:');
    console.log(`  ✓ ANSI Escape Filtering: ${config.sanitization?.ansi_escapes?.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`  ✓ Character Whitelisting: ${config.sanitization?.character_whitelist?.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`  ✓ Pattern Detection: ${config.sanitization?.patterns?.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`  ✓ Rate Limiting: ${config.rate_limiting?.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`  ✓ Strict Mode: ${config.sanitization?.strict_mode ? 'ENABLED' : 'DISABLED'}`);
    console.log('');

    // Create and start proxy server
    const proxy = new MCPProxyServer({
      port: config.proxy?.port,
      host: config.proxy?.host,
      mcpServerUrl: config.proxy?.mcp_server_url
    });

    // Handle security events
    proxy.on('security-event', (event) => {
      logger.security('Security event detected', event);
      
      // You can add custom handling here, such as:
      // - Send alerts
      // - Update firewall rules
      // - Block IP addresses
      // - Generate reports
    });

    // Start the proxy
    await proxy.start();

    const address = `ws://${config.proxy?.host || '0.0.0.0'}:${config.proxy?.port || 8080}`;
    console.log(`Proxy listening on: ${address}`);
    console.log(`Forwarding to MCP server: ${config.proxy?.mcp_server_url || 'ws://localhost:3000'}`);
    console.log('');
    console.log('Press Ctrl+C to stop the proxy');

    // Handle shutdown signals
    const shutdown = async (signal: string) => {
      console.log(`\nReceived ${signal}, shutting down gracefully...`);
      
      try {
        await proxy.stop();
        logger.info('Proxy stopped successfully');
        process.exit(0);
      } catch (error) {
        logger.error('Error during shutdown', { error: (error as Error).message });
        process.exit(1);
      }
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));

    // Optional: Status endpoint for monitoring
    if (config.monitoring?.status_endpoint) {
      const http = require('http');
      const statusServer = http.createServer((req: any, res: any) => {
        if (req.url === '/status') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'healthy',
            stats: proxy.getStats(),
            timestamp: new Date().toISOString()
          }));
        } else {
          res.writeHead(404);
          res.end('Not Found');
        }
      });

      const statusPort = config.monitoring.status_port || 9090;
      statusServer.listen(statusPort, () => {
        console.log(`Status endpoint available at: http://localhost:${statusPort}/status`);
      });
    }

  } catch (error) {
    logger.error('Failed to start proxy', { error: (error as Error).message, stack: (error as Error).stack });
    process.exit(1);
  }
}

// Run the proxy
main().catch((error) => {
  logger.error('Fatal error', { error: (error as Error).message, stack: (error as Error).stack });
  process.exit(1);
});