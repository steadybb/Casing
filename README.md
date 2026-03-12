```markdown
# 🔗 Redirector Pro - Advanced URL Redirection System

<div align="center">

![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)
![Node](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![PRs](https://img.shields.io/badge/PRs-welcome-orange.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue)

**A sophisticated URL redirection service with bot detection, QR codes, real-time analytics, and an elegant admin dashboard.**

[Features](#✨-features) • [Installation](#🚀-installation) • [Configuration](#⚙️-configuration) • [API](#📡-api) • [Screenshots](#📸-screenshots)

</div>

---

## ✨ Features

### 🛡️ **Advanced Bot Detection**
- Multi-factor bot detection with scoring system
- Device-aware thresholds (mobile-friendly)
- Real-time bot blocking with statistics
- Support for headless browsers detection
- Customizable bot redirect URLs

### 📱 **Mobile Optimized**
- Super lenient verification for real mobile devices
- Mobile-specific rate limiting (30 requests/min)
- Responsive admin dashboard
- Touch-friendly UI components

### 🎯 **QR Code Generation**
- On-demand QR code generation for any link
- Download QR codes as PNG
- QR code caching for performance
- Optional QR display before redirect

### 📊 **Real-time Analytics**
- Live traffic monitoring with Socket.IO
- Device distribution charts
- Geographic tracking (via IPinfo)
- Bot blocking statistics
- Request rate monitoring

### 🔐 **Security Features**
- Helmet.js security headers
- CSP with nonce-based script execution
- Rate limiting per device type
- Session-based admin authentication
- Multi-layer URL encoding/obfuscation

### 🎨 **Beautiful Admin UI**
- Modern, responsive dashboard
- Real-time charts with Chart.js
- Live request logs
- Link generator with QR options
- System configuration interface
- Cache management tools

### ⚡ **Performance**
- Multiple caching layers (Geo, Device, QR, Links)
- Compression enabled
- Memory-efficient design
- Configurable TTL for links

---

## 🚀 Installation

### Prerequisites
- Node.js >= 16.0.0
- npm or yarn
- (Optional) IPinfo token for geolocation

### Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/redirector-pro.git
cd redirector-pro

# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env

# Generate secure password hash
node -e "console.log(require('bcryptjs').hashSync('your-secure-password', 10))"

# Edit .env with your settings
nano .env

# Start server
npm start
```

Docker Installation

```bash
# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 10000
CMD ["node", "server.js"]
EOF

# Build image
docker build -t redirector-pro .

# Run container
docker run -p 10000:10000 \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD_HASH=your-hash \
  -e METRICS_API_KEY=your-key \
  redirector-pro
```

PM2 Production Deployment

```bash
# Install PM2 globally
npm install -g pm2

# Start with PM2
pm2 start server.js --name redirector-pro

# Monitor logs
pm2 logs redirector-pro

# Save PM2 configuration
pm2 save
pm2 startup
```

---

⚙️ Configuration

Environment Variables

Create a .env file:

```env
# Server Configuration
PORT=10000
NODE_ENV=production

# Security (CHANGE THESE!)
SESSION_SECRET=your-very-secure-session-secret-32-chars-min
ADMIN_USERNAME=admin
# Generate with: node -e "console.log(require('bcryptjs').hashSync('your-password', 10))"
ADMIN_PASSWORD_HASH=$2a$10$XQ9ZwZQ9ZwZQ9ZwZQ9ZwZu

# Link Configuration
TARGET_URL=https://your-target-site.com
LINK_TTL=30m
BOT_URLS=https://www.microsoft.com,https://www.apple.com,https://www.google.com

# External Services
IPINFO_TOKEN=your-ipinfo-token
METRICS_API_KEY=your-metrics-api-key
```

TTL Format Examples

Format Description Example
30m 30 minutes LINK_TTL=30m
24h 24 hours LINK_TTL=24h
7d 7 days LINK_TTL=7d
3600 3600 seconds LINK_TTL=3600

---

📡 API

Public Endpoints

GET /g - Generate Link

```bash
curl "http://localhost:10000/g?t=https://example.com"
```

Response:

```json
{
  "url": "http://localhost:10000/v/abc123",
  "expires": 1800,
  "expires_human": "30 minutes",
  "id": "abc123"
}
```

GET /v/:id - Access Redirect

```bash
curl "http://localhost:10000/v/abc123"
```

GET /qr - Generate QR Code

```bash
curl "http://localhost:10000/qr?url=https://example.com&size=300"
```

Response:

```json
{
  "qr": "data:image/png;base64,...",
  "url": "https://example.com"
}
```

GET /qr/download - Download QR as PNG

```bash
curl "http://localhost:10000/qr/download?url=https://example.com" --output qrcode.png
```

GET /expired - Expired Link Page

```bash
curl "http://localhost:10000/expired?target=https://example.com"
```

Health Checks

```bash
curl "http://localhost:10000/ping"
curl "http://localhost:10000/health"
curl "http://localhost:10000/status"
```

Protected Endpoints

GET /metrics - System Metrics

```bash
curl -H "X-API-Key: your-key" "http://localhost:10000/metrics"
```

Response:

```json
{
  "links": 156,
  "totals": {
    "requests": 1234567,
    "blocks": 45678,
    "successes": 1188889
  },
  "devices": {
    "mobile": 550000,
    "desktop": 630000,
    "tablet": 45000,
    "bot": 45678
  }
}
```

Admin Endpoints

Endpoint Method Description
/admin GET Admin dashboard
/admin/login POST Login
/admin/logout POST Logout
/admin/config POST Save config
/admin/clear-cache POST Clear all caches
/admin/export-logs GET Download logs

---

📸 Screenshots

```
┌─────────────────────────────────────┐
│  🔗 Redirector Pro Admin            │
├─────────────────────────────────────┤
│  📊 STATS                           │
│  ┌──────┐ ┌──────┐ ┌──────┐       │
│  │ 1.2M │ │ 156  │ │ 98%  │       │
│  │ Reqs │ │Links │ │Success│       │
│  └──────┘ └──────┘ └──────┘       │
├─────────────────────────────────────┤
│  📈 REAL-TIME TRAFFIC               │
│  150 │        ╭╮                    │
│  100 │       ╭╯╰╮                   │
│   50 │    ╭╮╭╯  ╰╮                  │
│    0 └────╯╰╯────╰──────────────── │
│      12:00   12:01   12:02         │
├─────────────────────────────────────┤
│  📱 DEVICES                         │
│  Mobile:   45%  ████████░░░░░░     │
│  Desktop:  52%  ██████████░░░░     │
│  Tablet:   2%   ░░░░░░░░░░░░░░     │
│  Bot:      1%   ░░░░░░░░░░░░░░     │
└─────────────────────────────────────┘
```

---

🔒 Security Best Practices

1. Change default credentials immediately
   ```bash
   # Generate new password hash
   node -e "console.log(require('bcryptjs').hashSync('new-password', 10))"
   ```
2. Use HTTPS in production
   ```bash
   # Behind Nginx/Apache with SSL
   # Or use Let's Encrypt
   ```
3. Set strong SESSION_SECRET
   ```bash
   node -e "console.log(crypto.randomBytes(32).toString('hex'))"
   ```
4. Regularly rotate API keys
5. Monitor logs for suspicious activity
6. Keep dependencies updated
   ```bash
   npm audit fix
   npm update
   ```

---

📊 Performance Tuning

Cache Configuration

```javascript
// In server.js - Adjust cache TTLs
const geoCache = new NodeCache({ stdTTL: 86400 }); // 24 hours
const deviceCache = new NodeCache({ stdTTL: 300 }); // 5 minutes
const qrCache = new NodeCache({ stdTTL: 3600 }); // 1 hour
```

Rate Limiting

```javascript
// Device-specific limits
max: (req) => {
  if (req.deviceInfo.isBot) return 2;      // Bots: 2/min
  if (req.deviceInfo.isMobile) return 30;  // Mobile: 30/min
  if (req.deviceInfo.isTablet) return 25;  // Tablet: 25/min
  return 15;                                // Desktop: 15/min
}
```

Bot Detection Thresholds

```javascript
// Adjust scoring thresholds
const botThreshold = deviceInfo.isMobile ? 20 : 65;
// Lower = more permissive, Higher = more strict
```

---

🛠️ Development

Project Structure

```
redirector-pro/
├── server.js              # Main application
├── package.json           # Dependencies
├── .env                   # Environment variables
├── config.json            # Runtime configuration
├── clicks.log             # Click logs
├── requests.log           # Request logs
├── success.log            # Success logs
└── README.md              # Documentation
```

Development Commands

```bash
# Run with hot-reload
npm install -g nodemon
nodemon server.js

# Debug mode
DEBUG=true node server.js

# Check for vulnerabilities
npm audit

# Update dependencies
npm update
```

---

🚦 Testing

Quick Test Script

```bash
#!/bin/bash
# test.sh

# Generate link
echo "Generating link..."
RESPONSE=$(curl -s "http://localhost:10000/g?t=https://example.com")
URL=$(echo $RESPONSE | grep -o 'http://[^"]*')
echo "Link: $URL"

# Test redirect
echo "Testing redirect..."
curl -L -v $URL

# Generate QR
echo "Generating QR..."
curl "http://localhost:10000/qr?url=$URL" | jq .
```

Load Test

```bash
# Install siege
sudo apt-get install siege

# Run load test
siege -c100 -t60s http://localhost:10000/ping
```

---

🤝 Contributing

1. Fork the repository
2. Create feature branch (git checkout -b feature/AmazingFeature)
3. Commit changes (git commit -m 'Add AmazingFeature')
4. Push to branch (git push origin feature/AmazingFeature)
5. Open Pull Request

Development Guidelines

· Follow existing code style
· Add comments for complex logic
· Update documentation
· Ensure all tests pass

---

📝 License

MIT License

Copyright (c) 2024 Redirector Pro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

🙏 Acknowledgments

· Express.js - Web framework
· Socket.IO - Real-time engine
· Chart.js - Beautiful charts
· QRCode - QR generation
· IPinfo - Geolocation API
· Helmet - Security headers

---

📞 Support

· Issues: GitHub Issues
· Email: support@redirector-pro.com
· Twitter: @redirectorpro

---

⭐ Star History

If you find this project useful, please consider giving it a star! It helps others discover it.

---

<div align="center">Made with ❤️ for the open-source community

⬆ Back to Top

</div>
