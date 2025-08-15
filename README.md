# MCP Security Proxy

A security-focused proxy server for the Model Context Protocol (MCP) that protects against injection attacks, ANSI hijacking, and other security vulnerabilities.

## Overview

The MCP Security Proxy addresses critical security vulnerabilities in MCP implementations, including CVE-2025-6514 (Remote Code Execution via command injection). It acts as a transparent security layer between MCP clients and servers, sanitizing all communications while maintaining protocol compatibility.

### Key Security Features

- **Input Sanitization**: Character whitelisting, ANSI escape sequence filtering
- **Attack Pattern Detection**: Command injection, path traversal, prompt injection
- **Rate Limiting**: Per-client and per-method request throttling
- **Audit Logging**: Comprehensive security event tracking
- **Protocol Validation**: JSON-RPC message structure validation

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd mcproxy

# Install dependencies
npm install

# Build the project
npm run build
```

### Basic Usage

```bash
# Start the proxy with default settings
npm start

# Start with custom configuration
npm start -- --config custom-config.yaml --port 8080

# Start with specific MCP server
npm start -- --server ws://localhost:3000 --verbose
```

### Configuration

Copy the example configuration and customize as needed:

```bash
cp mcproxy-config.example.yaml mcproxy-config.yaml
```

Edit `mcproxy-config.yaml` to configure security policies, rate limits, and server settings.

### Connecting MCP Components

Once the proxy is running, you need to configure your MCP clients and servers to use it:

#### 1. Start your MCP Server

First, start your MCP server on its normal port (e.g., 3000):

```bash
# Example MCP server
your-mcp-server --port 3000
```

#### 2. Start the Security Proxy

Start the proxy pointing to your MCP server:

```bash
# Proxy listens on 8080, forwards to server on 3000
npm start -- --port 8080 --server ws://localhost:3000
```

#### 3. Configure MCP Clients

Update your MCP clients to connect to the proxy instead of directly to the server:

**Before (Direct Connection):**
```javascript
const client = new MCPClient('ws://localhost:3000');
```

**After (Through Proxy):**
```javascript
const client = new MCPClient('ws://localhost:8080');
```

**Claude Desktop Configuration:**
If using with Claude Desktop, update your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "your-server": {
      "command": "node",
      "args": ["your-server.js"],
      "env": {
        "MCP_SERVER_URL": "ws://localhost:8080"
      }
    }
  }
}
```

**Environment Variables:**
Many MCP implementations use environment variables:

```bash
# Point client to proxy
export MCP_SERVER_URL=ws://localhost:8080

# Or for specific implementations
export MCP_PROXY_URL=ws://localhost:8080
export MCP_ENDPOINT=ws://localhost:8080
```

#### 4. Network Configuration

For remote deployments:

```bash
# Proxy accessible from other machines
npm start -- --host 0.0.0.0 --port 8080 --server ws://internal-server:3000

# Clients connect to proxy's external IP
# Client: ws://proxy-server-ip:8080
# Proxy forwards to: ws://internal-server:3000
```

#### 5. TLS/SSL Configuration

For production with HTTPS/WSS:

```bash
# Configure proxy with TLS
npm start -- --port 8443 --server wss://secure-mcp-server:3000

# Clients use secure connection
# Client connects to: wss://your-domain:8443
```

## Architecture

```
┌─────────────┐    ┌──────────────────────────────┐    ┌─────────────┐
│ MCP Client  │───▶│    MCP Security Proxy        │───▶│ MCP Server  │
└─────────────┘    │                              │    └─────────────┘
                   │  1. Input Sanitization       │
                   │  2. Pattern Detection        │
                   │  3. Rate Limiting            │
                   │  4. Message Validation       │
                   │  5. Audit Logging            │
                   └──────────────────────────────┘
```

The proxy operates as a WebSocket server that:

1. **Accepts connections** from MCP clients
2. **Sanitizes all input** through multiple security filters
3. **Forwards clean messages** to the configured MCP server
4. **Logs security events** for monitoring and compliance
5. **Returns responses** to clients with output sanitization

## Security Features

### Input Sanitization

**Character Whitelisting**
- Default: ASCII printable characters only (0x20-0x7E)
- Configurable character ranges
- Automatic removal of control characters and zero-width Unicode

**ANSI Escape Sequence Protection**
- Strips terminal control sequences that could hijack consoles
- Prevents cursor manipulation and screen clearing attacks
- Configurable actions: strip, reject, or encode

### Attack Pattern Detection

**Command Injection Prevention**
- Detects shell metacharacters: `; | & $ ( ) { } [ ] < > \``
- Blocks common injection patterns
- Configurable pattern rules with custom actions

**Path Traversal Protection**
- Blocks `../` and `..\\` sequences
- Prevents directory traversal attacks
- URL-encoded pattern detection

**Prompt Injection Detection**
- Identifies attempts to override system instructions
- Detects patterns like "ignore previous", "system:", "assistant:"
- Configurable severity levels and responses

### Rate Limiting

**Multi-Level Protection**
- Global rate limits across all connections
- Per-client request throttling
- Per-method rate limiting for specific MCP tools
- Configurable time windows and burst allowances

### Monitoring and Logging

**Security Event Logging**
- All sanitization actions logged with context
- Failed rate limit attempts tracked
- Pattern detection events recorded
- Structured JSON logging format

**Audit Trail**
- Complete message flow tracking
- Client connection lifecycle events
- Configuration change logging
- Integration with external log aggregation systems

## Configuration

### Basic Configuration

```yaml
proxy:
  port: 8080
  host: "0.0.0.0"
  mcp_server_url: "ws://localhost:3000"
  max_connections: 100

sanitization:
  strict_mode: false
  character_whitelist:
    enabled: true
    allowed_ranges: [[0x20, 0x7E]]
  ansi_escapes:
    enabled: true
    action: "strip"
  patterns:
    enabled: true
    rules:
      - name: "command_injection"
        pattern: "[;&|`$(){}\\[\\]<>]"
        action: "reject"

rate_limiting:
  enabled: true
  per_client:
    requests_per_minute: 60
    requests_per_hour: 1000
```

### Environment Variables

Override configuration with environment variables:

```bash
export MCP_PROXY_PORT=8080
export MCP_PROXY_HOST=0.0.0.0
export MCP_PROXY_STRICT_MODE=true
export MCP_PROXY_LOG_LEVEL=debug
```

## CLI Options

```bash
Usage: mcproxy [options]

Options:
  -c, --config <path>     Path to configuration file (default: "mcproxy-config.yaml")
  -p, --port <number>     Port to listen on (default: "8080")
  -h, --host <address>    Host to bind to (default: "0.0.0.0")
  -s, --server <url>      MCP server URL (default: "ws://localhost:3000")
  -v, --verbose          Enable verbose logging
  --strict               Enable strict mode (reject all unsafe content)
  --help                 Display help for command
  --version              Display version number
```

## Development

### Project Structure

```
mcproxy/
├── src/
│   ├── index.ts                 # Main entry point and CLI
│   ├── proxy/                   # WebSocket proxy implementation
│   ├── filters/                 # Security filters
│   ├── security/                # Rate limiting and sanitization
│   ├── monitoring/              # Logging and metrics
│   └── config/                  # Configuration management
├── tests/                       # Test suite
├── mcproxy-config.yaml         # Configuration file
└── package.json                # Dependencies and scripts
```

### Available Scripts

```bash
# Development with hot reload
npm run dev

# Build TypeScript
npm run build

# Run tests
npm test

# Run tests in watch mode
npm test:watch

# Run security-specific tests
npm run test:security

# Lint code
npm run lint

# Type checking
npm run typecheck

# Format code
npm run format
```

### Testing

The project includes comprehensive tests for all security features:

```bash
# Run all tests
npm test

# Run with coverage
npm test -- --coverage

# Test specific components
npm test -- sanitization
npm test -- rate-limiting
npm test -- patterns
```

### Adding Security Patterns

1. Edit the configuration file to add new pattern rules:

```yaml
sanitization:
  patterns:
    rules:
      - name: "custom_pattern"
        pattern: "your-regex-here"
        action: "reject"
        severity: "high"
```

2. Test the new pattern:

```bash
npm run test:security
```

## Production Deployment

### Docker Deployment

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY dist/ ./dist/
COPY mcproxy-config.yaml ./
EXPOSE 8080
CMD ["npm", "start"]
```

### Security Checklist

- [ ] TLS enabled for client connections
- [ ] Firewall rules configured
- [ ] Rate limits set appropriately for your use case
- [ ] Logging configured to secure location
- [ ] Configuration file permissions restricted
- [ ] Regular security updates scheduled
- [ ] Monitoring and alerting configured

### Performance Tuning

**Connection Limits**
- Adjust `max_connections` based on server capacity
- Monitor connection count and response times

**Rate Limiting**
- Tune limits based on legitimate usage patterns
- Implement burst allowances for bursty workloads

**Logging**
- Balance security logging with performance
- Use structured logging for better analysis
- Consider log rotation and archival

## Security Considerations

### Threat Model

The proxy protects against:

- **CVE-2025-6514**: Command injection through MCP tool parameters
- **Console hijacking**: ANSI escape sequence attacks
- **Prompt injection**: Attempts to override AI system instructions
- **Path traversal**: File system access outside intended directories
- **Rate abuse**: Excessive request patterns

### Limitations

- Does not protect against authentication bypass (authentication layer optional)
- Cannot detect all semantic attack patterns
- Performance overhead from deep packet inspection
- May block legitimate use of special characters if configured strictly

### Best Practices

1. **Enable strict mode** in production environments
2. **Monitor security logs** regularly for attack patterns
3. **Tune rate limits** based on legitimate usage
4. **Keep patterns updated** as new threats emerge
5. **Test thoroughly** with your specific MCP server implementation

## Troubleshooting

### Common Issues

**Legitimate messages being blocked**
- Check character whitelist configuration
- Review pattern rules for false positives
- Enable debug logging to see what's filtered

**Performance issues**
- Adjust rate limiting parameters
- Check logging configuration
- Monitor resource usage

**Connection failures**
- Verify MCP server URL and connectivity
- Check firewall and network configuration
- Review proxy logs for connection errors

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
npm start -- --verbose
# or
export MCP_PROXY_LOG_LEVEL=debug
npm start
```

## Todo

- [ ] Authentication layer
- [ ] Role-based access control (RBAC)
- [ ] Extended metrics and monitoring
- [ ] Docker containerization

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and add tests
4. Run the test suite: `npm test`
5. Submit a pull request

### Code Style

- Use TypeScript strict mode
- Follow existing naming conventions
- Add JSDoc comments for public APIs
- Include tests for new security features

## License

MIT License - see LICENSE file for details.

## Security Reporting

For security vulnerabilities, please contact the maintainers directly rather than opening public issues.

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io)
- [CVE-2025-6514 Details](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)
- [OWASP Input Validation Guide](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)