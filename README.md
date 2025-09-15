# Gravatar Username Scraper

"In October 2020, a security researcher published a technique for scraping large volumes of data from Gravatar, the service for providing globally unique avatars . 167 million names, usernames and MD5 hashes of email addresses used to reference users' avatars were subsequently scraped and distributed within the hacking community. 114 million of the MD5 hashes were cracked and distributed alongside the source hash, thus disclosing the original email address and accompanying data. Following the impacted email addresses being searchable in HIBP, Gravatar release an FAQ detailing the incident." Was something I read on HIBP and on seeing this I got curious if Gravatar have implemented any fix/prevenetative measures for the scraping of data on their platform. Upon researching it I found they made it so you can no longer scrape via userID which is great! Only issue being that's the only measure they added. Gravatar still has no ratelimits aside from checking TLS information and due to this you can easily make a script such as this one and scrape email hashes from their entire user list given enough time. After running this for around a day I ended up with millions of lines of PII from their userbase seeing as though the email addresses are just stored within hashes that are quite frankly not difficult at all to crack. Not sure why Gravatar haven't properly integrated deterrants for scraping like this but for now this is still completely viable and in my opinion Gravatar should be avoided until further fixes are put in place.

## Overview

This tool systematically generates and tests usernames (3-12 characters) against the Gravatar API to discover valid user profiles. It employs advanced evasion techniques to avoid detection and rate limiting.

## Features

### Core Functionality
- **Username Generation**: Systematically generates all possible usernames from 3 to 12 characters (a-z)
- **High-Performance**: Concurrent processing with 5,000 workers by default
- **CSV Output**: Results saved to `gravatar_results_3to12.csv`
- **Real-time Progress**: Live progress reporting with ETA calculations

### Evasion Techniques
- **TLS Fingerprint Randomization**: Randomizes cipher suites, curve preferences, and TLS versions
- **User Agent Rotation**: Cycles through 20+ different user agents (curl, wget, HTTPie, etc.)
- **HTTP Header Randomization**: Randomly adds/removes headers like Accept-Encoding, Connection, Cache-Control
- **Request Timing**: Random delays between 5-100ms per request
- **Connection Management**: Disables keep-alives and varies connection pool settings
- **TLS Config Refresh**: Refreshes TLS configuration every 50-150 requests

## Installation

### Prerequisites
- Go 1.19 or higher
- Network connection

### Setup
```bash
git clone <repository-url>
cd "gravatar scraper"
go mod init gravatar-scraper
go mod tidy
```

## Usage

### Basic Execution
```bash
go run main.go
```

### Building Binary
```bash
go build -o gravatar-scraper main.go
./gravatar-scraper
```

## Configuration

### Default Settings
```go
const (
    minLength   = 3      // Minimum username length
    maxLength   = 12     // Maximum username length  
    numWorkers  = 5000   // Concurrent workers
    timeout     = 5 * time.Second
)
```

### Customization
Modify constants in `main()` function to adjust:
- **Username Length Range**: Change `minLength` and `maxLength`
- **Worker Count**: Adjust `numWorkers` based on system capabilities
- **Timeout**: Modify request timeout duration

## Output Format

### CSV Structure
```csv
Username,Hash,ProfileURL,DisplayName,AboutMe,ThumbnailURL
example,abc123...,https://gravatar.com/example,John Doe,Bio text,https://...
```

### Progress Output
```
Scanning usernames from 3 to 12 characters
Total usernames to check: 321,257,406,234
Estimated time (conservative): 17.8 hours
Progress: 0.01% (32125/321257406234) | Found: 15 | Rate: 89.2/s | ETA: 17.8h
Found user: john (John Smith)
```

## Performance Metrics

### Scale
- **Total Combinations**: ~321 billion usernames (3-12 chars)
- **Estimated Runtime**: 15-20 hours with 5,000 workers
- **Rate**: ~50-100 requests/second (depends on network/rate limiting)

### Resource Usage
- **Memory**: ~50-100MB
- **CPU**: Moderate (mainly I/O bound)
- **Network**: High bandwidth usage

## Security Considerations

### Evasion Features
- **Fingerprint Diversity**: Multiple TLS configurations to avoid detection
- **Traffic Distribution**: Randomized timing and headers
- **Connection Patterns**: Varied connection management

### Rate Limiting
- Built-in delays and randomization
- Distributed load across multiple connection patterns
- Graceful handling of 403/blocked responses

### Detection Avoidance
- Mimics legitimate HTTP clients
- Randomizes request characteristics
- Avoids predictable patterns

### Post-Processing
1. **Deduplication**: Remove duplicate entries across multiple runs
2. **Email Enrichment**: Cross-reference with hash-to-email databases
3. **Data Validation**: Verify profile information accuracy

## Troubleshooting

### Common Issues

#### Rate Limiting
```
⚠️  Request blocked (403 HTML) for username: example
```
**Solution**: Reduce worker count or increase delays

#### Memory Issues
**Solution**: Reduce `numWorkers` constant

#### Network Timeouts
**Solution**: Increase `timeout` value or check network connectivity

### Performance Optimization

#### Increase Speed
- Increase `numWorkers` (carefully monitor for rate limiting)
- Optimize network configuration
- Use faster DNS servers

#### Reduce Detection
- Decrease `numWorkers`
- Increase random delays
- Modify user agent pool

## Legal and Ethical Use

### Important Notes
- **Professional Use**: Intended for authorized security testing and research
- **Rate Limiting**: Respects service limitations and implements delays
- **No Abuse**: Designed to avoid overloading target services
- **Compliance**: Ensure compliance with applicable laws and terms of service

### Responsible Usage
- Only use on systems you own or have explicit permission to test
- Respect rate limits and implement appropriate delays
- Do not use for malicious purposes or unauthorized access
- Consider the impact on target services

## Technical Details

### Architecture
- **Concurrent Processing**: Worker pool pattern with goroutines
- **Channel Communication**: Producer-consumer pattern for username distribution
- **Memory Efficient**: Streaming processing without loading all data into memory

### Dependencies
- Standard Go library only
- No external dependencies required
- Cross-platform compatibility

### Algorithm
1. **Generation**: Systematic username generation (lexicographic order)
2. **Distribution**: Work distribution across worker pool
3. **Validation**: HTTP requests to Gravatar API endpoints
4. **Processing**: JSON parsing and data extraction
5. **Output**: CSV writing with concurrent access protection

## Contributing

### Code Structure
- `main()`: Entry point and configuration
- `worker()`: Individual worker goroutine
- `checkGravatar()`: Core API interaction logic
- `generateUsernamesRange()`: Username generation logic
- `progressReporter()`: Progress tracking and display

### Testing
- Verify output format with small datasets
- Test evasion effectiveness
- Monitor rate limiting behavior

## License

Use responsibly and in accordance with applicable laws and service terms.

---

**Disclaimer**: This tool is for authorized security testing and research purposes only. Users are responsible for compliance with applicable laws and service terms. 
