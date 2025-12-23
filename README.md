# Burp Insights

A go library and simple command-line tool for parsing and analyzing Burp Suite project files. Extract HTTP history, site maps, scanner findings, and more from `.burp` files with ease.

## Features

- Parse Burp Suite project files (`.burp`)
- Extract and analyze HTTP history
- Display site map trees
- Generate HTML reports
- Search across project content
- Export data in multiple formats (JSON, JSONL, CSV, HAR, Table)
- Filtering and analysis capabilities

## Installation

```bash
go install github.com/bmm-sec/burp-insights/cmd/burp-insights@latest
```

Or build from source:

```bash
git clone https://github.com/bmm-sec/burp-insights.git
cd burp-insights
go build -o bin/burp-insights ./cmd/burp-insights
```

## Usage

### Basic Commands

```bash
# Display project metadata and statistics
burp-insights info <path-to-burp-file>

# List HTTP history entries
burp-insights history <path-to-burp-file>

# List Scanner issues
burp-insights issues <path-to-burp-file>

# List Burp tasks (UI task list)
burp-insights tasks <path-to-burp-file>

# Show site map tree
burp-insights sitemap <path-to-burp-file>

# Generate HTML report
burp-insights report <path-to-burp-file> -o report.html

# Search across project content
burp-insights search <query> <path-to-burp-file>

# Export data
burp-insights export <path-to-burp-file> -f json -o output.json
```

### Output Formats

Supported export formats:
- `table` - Formatted table (default)
- `json` - JSON format
- `jsonl` - JSON Lines format
- `csv` - CSV format
- `har` - HAR (HTTP Archive) format

### Global Flags

- `-f, --format string` - Output format (default: "table")
- `-o, --output string` - Write output to file
- `--no-color` - Disable colored output
- `--quiet` - Suppress non-essential output
- `-v, --verbose` - Verbose output
- `-h, --help` - Show help information
