# emed_utilities

Utility library for eMed — database helpers, shared logging, and common tools.

## Requirements

- Python 3.11+
- MySQL 8+

## Setup

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/Mac
.venv\Scripts\activate           # Windows

# Install dependencies (including dev tools)
pip install -e ".[dev]"

# Copy the env template and fill in your values
cp .env.example .env
```

## Configuration

All configuration is driven by environment variables. Copy `.env.example` to `.env` and set the values:

| Variable | Description |
|---|---|
| `DB_HOST` | MySQL host |
| `DB_PORT` | MySQL port (default 3306) |
| `DB_NAME` | Database name |
| `DB_USER` | Database username |
| `DB_PASSWORD` | Database password |
| `LOG_LEVEL` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `LOG_FORMAT` | `json` or `text` (default `text`) |

## Project structure

```
emed_utilities/
├── config/          # Settings / environment loading
├── db/              # Database connection pool
└── logging_config/  # Logger factory
tests/               # pytest test suite
```

## Running tests

```bash
pytest
```
