# Launchium Token Creator

A professional Solana token creation platform with wallet integration and access control.

## Features

- **Wallet Integration**: Phantom wallet connection
- **Access Control**: Requires 2M+ LAUNCHIUM tokens
- **Modern UI**: Dark/light mode with orange-yellow gradient theme
- **Responsive Design**: Works on all devices
- **Sponsored Transactions**: Free token creation for eligible users
- **IPFS Metadata**: Automatic logo and metadata upload
- **Token-2022**: Latest Solana token standard

## Architecture

### Frontend (Vercel)
- **Static Site**: HTML, CSS, JavaScript
- **Wallet Integration**: Phantom wallet adapter
- **IPFS Upload**: User logo upload via Pinata

### Backend (Railway)
- **Express.js**: RESTful API server
- **Token Creation**: Solana Token-2022 program
- **Sponsored Wallet**: Server-side transaction signing
- **Rate Limiting**: Built-in API protection

## Deployment

### Prerequisites

1. **Pinata Account**: For IPFS metadata storage
2. **Solana Wallet**: With SOL for transaction fees
3. **Helius RPC**: For Solana blockchain access
4. **Vercel Account**: For frontend hosting
5. **Railway Account**: For backend hosting

### Environment Variables

#### Railway Backend
```env
PINATA_API_KEY=your_pinata_api_key
PINATA_SECRET_KEY=your_pinata_secret_key
SOLANA_PRIVATE_KEY=your_solana_private_key_base58
ALLOWED_ORIGINS=https://your-frontend.vercel.app
NODE_ENV=production
```

#### Vercel Frontend
```env
# No environment variables needed for frontend
# API URL is automatically detected based on hostname
```

### Deployment Steps

#### 1. Deploy Backend to Railway

1. Connect GitHub repository to Railway
2. Select `server.js` as entry point
3. Add environment variables
4. Deploy and get Railway URL

#### 2. Deploy Frontend to Vercel

1. Connect GitHub repository to Vercel
2. Set build command: `echo "Static site - no build needed"`
3. Set output directory: `./`
4. Deploy and get Vercel URL

#### 3. Update Cross-Platform URLs

1. Update `server.js` CORS with Vercel URL
2. Update `index.html` API_URL with Railway URL
3. Redeploy both services

## Local Development

```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your values

# Start development server
npm run dev

# Open browser
http://localhost:3001
```

## API Endpoints

### POST /create-token
Creates a new Solana token with provided metadata.

**Request Body:**
```json
{
  "name": "Token Name",
  "symbol": "TKN",
  "description": "Token description",
  "website": "https://example.com",
  "twitter": "@twitter",
  "logoFile": "base64_image_data",
  "walletAddress": "user_wallet_address"
}
```

**Response:**
```json
{
  "success": true,
  "mintAddress": "token_mint_address",
  "metadata": "ipfs_metadata_url"
}
```

### GET /health
Health check endpoint for monitoring.

## Security Features

- **CORS Protection**: Whitelist allowed origins
- **Rate Limiting**: Prevent API abuse
- **Input Validation**: Sanitize all user inputs
- **Wallet Verification**: On-chain balance verification
- **CSP Headers**: Content Security Policy protection

## Tech Stack

- **Frontend**: HTML5, CSS3, JavaScript ES6+
- **Backend**: Node.js, Express.js
- **Blockchain**: Solana, Token-2022 Program
- **Storage**: IPFS (Pinata)
- **Hosting**: Vercel (Frontend) + Railway (Backend)
- **Wallet**: Phantom Wallet Integration

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For support and questions, please open an issue on GitHub.

---

**Created by Launchium Team**