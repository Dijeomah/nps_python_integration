# NPS Integration - Complete Setup Guide

## Overview

This guide will walk you through setting up the NPS (National Payment Stack) integration for sending and receiving ISO 20022 PACS.008 payment messages.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Basic understanding of REST APIs
- NIBSS-provided credentials and certificates (for production)

## Step-by-Step Setup

### Step 1: Project Structure

Create the following directory structure:

```
nps-integration/
├── app.py
├── main.py
├── api_endpoints.py
├── signing.py
├── encryption.py
├── key_generator.py
├── requirements.txt
├── test_payment.py
├── README.md
└── SETUP_GUIDE.md
```

### Step 2: Install Dependencies

Create a virtual environment (recommended):

```bash
# Create virtual environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Generate Cryptographic Keys

Generate the required keys and certificates:

```bash
python key_generator.py
```

This creates:
- ✅ `private_key.pem` - Your private signing key
- ✅ `cert.pem` - Your self-signed certificate
- ✅ `nibss_public_key.pem` - Public key for encryption

**⚠️ Important for Production:**
- Replace `nibss_public_key.pem` with the actual public key from NIBSS
- Obtain a proper certificate from a Certificate Authority
- Keep `private_key.pem` secure and never commit it to version control

### Step 4: Configure Environment

Create a `.env` file (optional):

```bash
NPS_BASE_URL=https://198.51.100.204:8022
LOG_LEVEL=INFO
```

Or export environment variables:

```bash
export NPS_BASE_URL="https://your-nps-endpoint:8022"
```

### Step 5: Start the Application

Run the FastAPI server:

```bash
python app.py
```

You should see:

```
🚀 Starting NPS Integration API Server
====================================================================

📡 API will be available at: http://localhost:8000
📚 API Documentation: http://localhost:8000/docs
```

### Step 6: Verify Installation

Open your browser and navigate to:
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

You should see the interactive API documentation.

### Step 7: Run Tests

In a new terminal (keep the server running):

```bash
python test_payment.py
```

This will run a test suite covering:
- Health check
- NPS connection test
- Payment sending
- Input validation

## Understanding the Code Structure

### main.py
- Core FastAPI application
- Key loading and initialization
- PACS.008 XML template
- Configuration settings

### api_endpoints.py
- REST API endpoints
- Request validation with Pydantic
- Payment processing logic
- Error handling

### signing.py
- XML digital signature creation
- Signature verification
- Uses W3C XML Signature standard

### encryption.py
- AES-256-GCM encryption for message content
- RSA-OAEP for session key encryption
- XML Encryption standard implementation

### key_generator.py
- Generates RSA-2048 key pairs
- Creates self-signed certificates
- For testing purposes only

## API Endpoints

### 1. Health Check
```http
GET /health
```

Response:
```json
{
  "status": "healthy",
  "keys_loaded": {
    "private_key": true,
    "certificate": true,
    "nibss_public_key": true
  }
}
```

### 2. Send Payment
```http
POST /api/send-payment
Content-Type: application/json

{
  "amount": 5000.00,
  "debtor_name": "John Doe",
  "debtor_account": "0123456789",
  "debtor_bvn": "12345678901",
  "creditor_name": "Jane Smith",
  "creditor_account": "9876543210",
  "creditor_bvn": "10987654321",
  "narration": "Payment for services"
}
```

### 3. Receive Payment
```http
POST /api/receive-payment
Content-Type: application/xml

[Encrypted XML from NPS]
```

### 4. Test Connection
```http
POST /api/test-connection
```

## Message Flow Diagram

```
┌─────────────┐                              ┌─────────────┐
│  Your Bank  │                              │     NPS     │
│   System    │                              │   (NIBSS)   │
└──────┬──────┘                              └──────┬──────┘
       │                                            │
       │ 1. Create PACS.008 XML                    │
       │────────────────────────────────────►      │
       │                                            │
       │ 2. Sign with Private Key                  │
       │────────────────────────────────────►      │
       │                                            │
       │ 3. Encrypt with NIBSS Public Key          │
       │────────────────────────────────────►      │
       │                                            │
       │ 4. Send via HTTPS                         │
       │──────────────────────────────────────────►│
       │                                            │
       │                            5. Process      │
       │                         ◄──────────────────│
       │                                            │
       │ 6. Receive Response                       │
       │◄──────────────────────────────────────────│
       │                                            │
```

## Validation Rules

### Account Numbers
- Must be exactly 10 digits
- Numeric characters only
- No spaces or special characters

### BVN (Bank Verification Number)
- Must be exactly 11 digits
- Numeric characters only
- Must be valid according to NIBSS standards

### Amount
- Must be greater than 0
- Maximum 2 decimal places
- Currency is NGN (Nigerian Naira)

### Names
- Minimum 1 character
- Maximum 140 characters
- Alphanumeric and spaces allowed

## Security Best Practices

### 1. Key Management
```bash
# Set proper file permissions
chmod 600 private_key.pem
chmod 644 cert.pem
chmod 644 nibss_public_key.pem
```

### 2. Environment Variables
Never hardcode sensitive data. Use environment variables:

```python
import os
NPS_BASE_URL = os.getenv("NPS_BASE_URL")
```

### 3. SSL/TLS
Enable SSL verification in production:

```python
async with httpx.AsyncClient(verify=True) as client:
    # verify=True for production
```

### 4. Logging
Implement proper logging without exposing sensitive data:

```python
# Good
logger.info(f"Processing payment for transaction: {tx_id}")

# Bad - Don't log sensitive data
logger.info(f"BVN: {bvn}, Account: {account}")
```

## Troubleshooting

### Error: "Private key not loaded"
**Cause**: Keys haven't been generated
**Solution**: Run `python key_generator.py`

### Error: "Connection refused"
**Cause**: NPS endpoint not reachable
**Solution**:
- Check NPS_BASE_URL configuration
- Verify network connectivity
- Check firewall rules

### Error: "Invalid signature"
**Cause**: Wrong private key or certificate
**Solution**: Ensure you're using the correct key pair

### Error: "Encryption failed"
**Cause**: Wrong public key format
**Solution**: Verify NIBSS public key is in correct PEM format

### Error: "XML validation failed"
**Cause**: Invalid XML structure
**Solution**: Check PACS.008 template follows ISO 20022 standard

## Production Deployment

### 1. Update Configuration
```python
# Use production NPS endpoint
NPS_BASE_URL = "https://production.nps.nibss-plc.com.ng"

# Enable SSL verification
verify=True

# Use proper logging level
LOG_LEVEL = "WARNING"
```

### 2. Install Production Keys
Replace test keys with production keys from NIBSS:
- Obtain official certificate from CA
- Get NIBSS production public key
- Securely store private key

### 3. Set Up Monitoring
```python
# Add monitoring endpoints
@app.get("/metrics")
async def metrics():
    return {
        "transactions_processed": counter,
        "success_rate": success_rate,
        "average_response_time": avg_time
    }
```

### 4. Configure Reverse Proxy
Use nginx or similar:

```nginx
server {
    listen 443 ssl;
    server_name your-bank.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8000;
    }
}
```

### 5. Deploy with Systemd
Create `/etc/systemd/system/nps-api.service`:

```ini
[Unit]
Description=NPS Integration API
After=network.target

[Service]
Type=simple
User=nps-user
WorkingDirectory=/opt/nps-integration
ExecStart=/opt/nps-integration/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable nps-api
sudo systemctl start nps-api
```

## Support and Resources

- **NPS Documentation**: https://nps-documentation.nibss-plc.com.ng/
- **ISO 20022 Standard**: https://www.iso20022.org/
- **NIBSS Support**: support@nibss-plc.com.ng

## Next Steps

1. ✅ Complete setup and test locally
2. ✅ Run test suite successfully
3. ✅ Integrate with your core banking system
4. ✅ Obtain production credentials from NIBSS
5. ✅ Deploy to production environment
