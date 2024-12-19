# Access Log Analyzer

A Flask web application that analyzes Caddy access logs and provides visual statistics about traffic patterns, browsers, operating systems, and potential WordPress attack attempts.

## Features

- 📊 Real-time analysis of Caddy access logs
- 🌓 Dark/Light mode toggle with persistent preference
- 📱 Responsive design that works on desktop and mobile
- 🔒 Security-focused with WordPress attack attempt tracking
- 📈 Comprehensive statistics including:
  - Browser usage
  - Operating system distribution
  - IP address frequency
  - HTTP status codes
  - Most requested paths
  - Host statistics
  - WordPress attack attempts
- 📥 CSV export functionality for WordPress attack data

## Statistics Tracked

- Total requests
- IPv4 vs IPv6 distribution
- Top browsers
- Top operating systems
- Most active IP addresses
- HTTP status code distribution
- Most requested paths
- Host distribution
- WordPress admin access attempts

## Requirements

- Python 3.8+
- Flask 3.0.0
- user-agents 2.2.0

## Installation

1. Clone the repository: 

```bash
git clone https://github.com/yourusername/access-log-analyzer.git
cd access-log-analyzer
```

2. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Place your Caddy access log file as `access.json` in the project directory

5. Run the application:

```bash
python app.py
```

6. Open your browser and navigate to `http://localhost:5000` to view the statistics.

## Log File Format

The application expects a Caddy access log in JSON format. Each line should be a valid JSON object containing request information. Example format:

```json
{
"level": "info",
"ts": 1734584668.048232,
"logger": "http.log.access.log2",
"msg": "handled request",
"request": {
"remote_ip": "192.168.1.1",
"method": "GET",
"host": "example.com",
"uri": "/path",
"headers": {
"User-Agent": ["Mozilla/5.0 ..."]
}
},
"status": 200
}
```

## Configuration

The application reads from `access.json` by default. If you need to use a different file, modify the `load_log_entries()` function in `app.py`.

## Security Features

The application includes special tracking for WordPress-related security events:
- Monitors attempts to access wp-admin paths
- Tracks IPs making repeated WordPress-related requests
- Provides CSV export of WordPress attack attempts
- Shows detailed timestamps and paths for security analysis

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Flask
- Uses the user-agents library for User-Agent parsing
- Styled with custom CSS
- Icons from Font Awesome
