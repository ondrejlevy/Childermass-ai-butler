# Childermass - Personal Home Assistant Agent

A sophisticated personal assistant and home automation agent built on the Model Context Protocol (MCP), inspired by John Childermass from 'Jonathan Strange & Mr Norrell'.

## Overview

Childermass is a modular MCP-based agent system that integrates with various smart home services, communication tools, and information sources. The system consists of a main agent (Childermass) and specialized sub-agents for different domains.

## Project Structure

```
.
├── .opencode/
│   ├── agents/          # Agent configuration files
│   └── opencode.json    # MCP server configuration (DO NOT COMMIT)
├── src/
│   └── childermass/     # MCP server implementations
│       ├── calendar_mcp/    # Google Calendar integration
│       ├── contacts_mcp/    # Google Contacts integration
│       ├── gmail_mcp/       # Gmail integration
│       ├── keep_mcp/        # Google Keep notes
│       ├── mapy_mcp/        # Mapy.com mapping service
│       ├── memory_mcp/      # Persistent memory storage
│       ├── network_mcp/     # UniFi Network management
│       ├── places_mcp/      # Places/location services
│       ├── protect_mcp/     # UniFi Protect camera system
│       ├── tasks_mcp/       # Google Tasks integration
│       └── weather_mcp/     # Weather information
└── venv/                # Python virtual environment (DO NOT COMMIT)
```

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd Home
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

Each MCP server has its own setup script:

```bash
# Install specific MCP server
./src/childermass/<mcp-name>/setup.sh
```

Or install all at once:

```bash
for mcp in src/childermass/*/setup.sh; do
    bash "$mcp"
done
```

### 3. Configure Credentials

⚠️ **IMPORTANT**: Never commit credentials to git!

1. Copy the example configuration:
   ```bash
   cp .opencode/opencode.example.json .opencode/opencode.json
   ```

2. Edit `.opencode/opencode.json` with your actual credentials and paths

3. Configure individual MCP servers as needed:
   ```bash
   # Google Services (Gmail, Calendar, Tasks, Contacts)
   source venv/bin/activate
   PYTHONPATH=src python -m childermass.gmail_mcp.auth --setup
   
   # UniFi Protect (cameras)
   PYTHONPATH=src python -m childermass.protect_mcp.auth --setup
   
   # UniFi Network
   PYTHONPATH=src python -m childermass.network_mcp.auth --setup
   
   # Mapy.com API
   PYTHONPATH=src python -m childermass.mapy_mcp.auth --set-api-key YOUR_KEY
   ```

### 4. Test Installation

```bash
# Test a specific MCP server
PYTHONPATH=src python -m childermass.<mcp-name>.auth --test

# Run tests
PYTHONPATH=src pytest src/childermass/<mcp-name>/tests/ -v
```

## Available MCP Servers

### Communication & Productivity
- **gmail_mcp**: Email management and search
- **calendar_mcp**: Calendar events and scheduling
- **contacts_mcp**: Contact information management
- **tasks_mcp**: Task and todo list management
- **keep_mcp**: Note-taking (currently disabled)

### Smart Home
- **protect_mcp**: UniFi Protect camera system (10 tools)
- **network_mcp**: UniFi Network management (17 tools)

### Location & Information
- **mapy_mcp**: Czech mapping, routing, geocoding (9 tools)
- **places_mcp**: Place lookup and information
- **weather_mcp**: Weather forecasts and conditions

### Infrastructure  
- **memory_mcp**: Persistent memory for the agent

## Security

⚠️ **For comprehensive security information, please read [SECURITY.md](SECURITY.md)**

This project handles sensitive credentials and personal data. **NEVER commit**:

- `.opencode/opencode.json` (your actual configuration)
- Any `*-credentials.json` or `*-tokens*.json` files
- Files in `~/.childermass/` directory
- SQLite database files (`*.sqlite*`)
- Virtual environment files

Credentials are stored securely:
- **Google services**: OAuth tokens in system keyring
- **UniFi services**: Credentials in macOS Keychain / Linux Secret Service
- **Mapy.com**: API key in keyring or encrypted file
- **Rohlik**: Credentials in environment variables (NOT in git)

All MCP servers include:
- Input validation and sanitization
- Rate limiting (token bucket algorithm)
- Structured audit logging
- Error message sanitization

**Reporting Security Issues**: See [SECURITY.md](SECURITY.md) for responsible disclosure process.

## Development

### Running Tests

```bash
# All tests
PYTHONPATH=src pytest src/childermass/ -v

# Specific MCP server
PYTHONPATH=src pytest src/childermass/<mcp-name>/tests/ -v

# With coverage
PYTHONPATH=src pytest --cov=src/childermass --cov-report=html
```

### Adding a New MCP Server

1. Create directory: `src/childermass/<name>_mcp/`
2. Implement required files:
   - `__init__.py` - Package metadata
   - `server.py` - MCP server implementation
   - `client.py` - Service API client
   - `auth.py` - Authentication management
   - `security.py` - Validation and security
   - `requirements.txt` - Dependencies
   - `setup.sh` - Installation script
   - `README.md` - Documentation
   - `tests/` - Test suite

3. Add configuration to `.opencode/opencode.json`
4. Update this README

## Agent Configuration

Agent behavior is defined in `.opencode/agents/`:
- `childermass.md` - Main coordinator agent
- `radar.md` - Communications specialist (planned)
- `kreacher.md` - Security specialist (planned)
- `jorge.md` - Information curator (planned)

## Development & CI/CD

### Testing & Code Quality

All MCP servers include comprehensive testing and code quality checks:

```bash
# Using Make (recommended)
make help              # Show all available commands
make install           # Install development dependencies
make test              # Run all tests
make test-cov          # Run tests with coverage
make lint              # Check code quality
make format            # Auto-format code
make security          # Run security scans
make ci                # Run full CI pipeline locally

# Or manually
pytest src/ -v                                    # Run tests
ruff check src/                                   # Lint code
mypy src/ --ignore-missing-imports               # Type check
bandit -r src/                                    # Security scan
```

### GitHub Actions Workflows

Automated CI/CD pipelines run on every push and PR:

- **CI Pipeline** (`.github/workflows/ci.yml`)
  - Code linting with Ruff
  - Type checking with MyPy
  - Security auditing (pip-audit, Bandit, Safety)
  - Comprehensive test suite for all MCP servers
  - Coverage reporting

- **CodeQL Analysis** (`.github/workflows/codeql.yml`)
  - Advanced security vulnerability detection
  - Weekly automated scans

- **OSSF Scorecard** (`.github/workflows/scorecard.yml`)
  - Open source security best practices scoring
  - Supply chain security assessment

- **Secrets Scanning** (`.github/workflows/secrets-scan.yml`)
  - TruffleHog and GitLeaks for credential detection
  - Daily automated scans

### Dependabot

Automatic dependency updates configured for:
- All 11 MCP servers (Python dependencies)
- GitHub Actions
- Weekly schedule with automatic PRs

See [docs/CI_CD.md](docs/CI_CD.md) for detailed documentation.

### Pre-commit Hooks

Optional but recommended for local development:

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

Configuration: `.pre-commit-config.yaml`

## Troubleshooting

### Module Import Errors
Ensure `PYTHONPATH` is set:
```bash
export PYTHONPATH=/path/to/Home/src
```

### Keyring/Credential Issues
```bash
# Check keyring availability
python -c "import keyring; keyring.get_keyring()"

# Reset credentials
PYTHONPATH=src python -m childermass.<mcp-name>.auth --setup
```

### Connection Issues
- Verify network connectivity to services
- Check if UniFi devices are on local network
- Ensure API keys are valid and not expired

## Contributing

Pull requests are welcome. For major changes:
1. Open an issue first to discuss
2. Ensure all tests pass
3. Add tests for new features
4. Update documentation
5. **Never commit credentials or personal data**

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

This project uses several open-source libraries. All dependencies use permissive licenses (MIT, Apache 2.0, BSD) that are compatible with the project's MIT License. For detailed license information about third-party dependencies, see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

## Credits

Inspired by:
- John Childermass from "Jonathan Strange & Mr Norrell" by Susanna Clarke
- Saturnin from novels by Zdeněk Jirotka
- Alfred Pennyworth from DC Comics

Built with:
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- [FastMCP](https://github.com/jlowin/fastmcp)
- Various Google, UniFi, and Czech service APIs
