import express from 'express';
import cors from 'cors';
import { spawn } from 'child_process';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import path from 'path';
import axios from 'axios';
import FormData from 'form-data';

dotenv.config();

const app = express();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-hashes'", "https://cdnjs.cloudflare.com", "https://unpkg.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            connectSrc: ["'self'", "http://localhost:3001", "https://api.mainnet-beta.solana.com", "wss://api.mainnet-beta.solana.com", "https://solana-api.projectserum.com", "https://rpc.ankr.com", "https://solana-mainnet.g.alchemy.com", "https://mainnet.helius-rpc.com"]
        }
    }
}));

// CORS configuration - only allow specific origins
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:3001',
            'http://127.0.0.1:3001',
            'https://launchium.app',
            'https://token.launchium.app', // Production Vercel domain
            'https://your-frontend.vercel.app', // Will be updated with actual Vercel URL
            // Add your custom domain here if you have one
            ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [])
        ];
        
        // Allow requests with no origin (mobile apps, etc.)
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.warn(`CORS blocked origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('.', {
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('X-Content-Type-Options', 'nosniff');
        }
    }
}));

// Serve static files from public directory
app.use(express.static('public'));

// Rate limiting
const createTokenLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many token creation requests, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// IPFS Logo Upload Function
async function uploadLogoToIPFS(logoData) {
    try {
        if (!process.env.PINATA_API_KEY || !process.env.PINATA_SECRET_KEY) {
            throw new Error("Pinata credentials not configured");
        }

        // Convert base64 to buffer
        const base64Data = logoData.data.split(',')[1];
        const buffer = Buffer.from(base64Data, 'base64');
        
        const formData = new FormData();
        formData.append('file', buffer, {
            filename: logoData.name || 'logo.png',
            contentType: logoData.type || 'image/png'
        });
        
        formData.append('pinataMetadata', JSON.stringify({
            name: `Token Logo - ${logoData.name || 'logo'}`,
            keyvalues: {
                type: 'logo',
                platform: 'Launchium'
            }
        }));

        const response = await axios.post(
            'https://api.pinata.cloud/pinning/pinFileToIPFS',
            formData,
            {
                maxBodyLength: Infinity,
                headers: {
                    ...formData.getHeaders(),
                    'pinata_api_key': process.env.PINATA_API_KEY,
                    'pinata_secret_api_key': process.env.PINATA_SECRET_KEY
                },
                timeout: 30000
            }
        );

        const ipfsUrl = `https://gateway.pinata.cloud/ipfs/${response.data.IpfsHash}`;
        console.log(`[${new Date().toISOString()}] Logo uploaded to IPFS:`, ipfsUrl);
        return ipfsUrl;
        
    } catch (error) {
        console.error('Failed to upload logo to IPFS:', error.response?.data || error.message);
        // Return default logo if upload fails
        return 'https://gateway.pinata.cloud/ipfs/bafybeidv23lg2sz756fouki7wbyenqwfir64k74kyydghxzepj3g425lxi';
    }
}

// Input validation
const validateTokenInput = (data) => {
    const { name, symbol, description, website, twitter, logoUrl, logoFile } = data;
    
    if (!name || name.length > 50 || !/^[a-zA-Z0-9\s\-_]+$/.test(name)) {
        return { valid: false, error: 'Invalid token name' };
    }
    
    if (!symbol || symbol.length > 10 || !/^[A-Z0-9]+$/.test(symbol.toUpperCase())) {
        return { valid: false, error: 'Invalid token symbol' };
    }
    
    if (description && description.length > 500) {
        return { valid: false, error: 'Description too long' };
    }
    
    if (website && !/^https?:\/\/.+/.test(website)) {
        return { valid: false, error: 'Invalid website URL' };
    }
    
    if (twitter && !/^@?[a-zA-Z0-9_]{1,15}$/.test(twitter)) {
        return { valid: false, error: 'Invalid Twitter handle' };
    }
    
    if (logoUrl && !/^https?:\/\/.+/.test(logoUrl) && !/^data:image\//.test(logoUrl)) {
        return { valid: false, error: 'Invalid logo URL' };
    }
    
    // LogoFile validation if provided
    if (logoFile && logoFile.data && !logoFile.data.startsWith('data:image/')) {
        return { valid: false, error: 'Invalid logo file format' };
    }
    
    return { valid: true };
};

app.post('/create-token', createTokenLimiter, async (req, res) => {
    try {
        // Validate input
        const validation = validateTokenInput(req.body);
        if (!validation.valid) {
            console.error(`[${new Date().toISOString()}] Validation failed:`, validation.error);
            console.error('Request body keys:', Object.keys(req.body));
            return res.status(400).json({ error: validation.error });
        }
        
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        
        const { name, symbol, description, website, twitter, logoUrl, logoFile, walletAddress } = req.body;
        
        console.log(`[${new Date().toISOString()}] Token creation request:`, {
            name,
            symbol,
            hasLogoFile: !!logoFile,
            ip: req.ip
        });

        // Upload logo to IPFS if user provided one
        let finalLogoUrl = logoUrl;
        if (logoFile && logoFile.data) {
            console.log(`[${new Date().toISOString()}] Uploading logo to IPFS...`);
            res.write(`data: ${JSON.stringify({ step: 1, status: 'active', message: 'Uploading logo to IPFS...' })}\n\n`);
            finalLogoUrl = await uploadLogoToIPFS(logoFile);
        }
        
        // Create child process with security restrictions
        const tokenProcess = spawn('node', ['create-token.js'], {
            env: {
                ...process.env,
                NODE_ENV: 'production'
            },
            timeout: 300000, // 5 minutes timeout
            stdio: ['pipe', 'pipe', 'pipe']
        });
        
        let tokenInfo = {};
        let inputsSent = 0;
        let processTimeout;
        
        // Set process timeout
        processTimeout = setTimeout(() => {
            tokenProcess.kill('SIGTERM');
            res.write(`data: ${JSON.stringify({ error: 'Process timeout' })}\n\n`);
            res.end();
        }, 300000);
        
        // Send initial status
        res.write(`data: ${JSON.stringify({ step: 1, status: 'active' })}\n\n`);
        
        // Handle stdout
        tokenProcess.stdout.on('data', (data) => {
            const output = data.toString();
            
            // Sanitize output before logging
            const sanitizedOutput = output.replace(/[<>]/g, '');
            console.log('[Process]:', sanitizedOutput.substring(0, 200));
            
            // Send inputs based on prompts
            if (output.includes('Enter Token Name') && inputsSent === 0) {
                tokenProcess.stdin.write(`${name}\n`);
                inputsSent++;
            } else if (output.includes('Enter Token Symbol') && inputsSent === 1) {
                tokenProcess.stdin.write(`${symbol}\n`);
                inputsSent++;
            } else if (output.includes('Enter Token Description') && inputsSent === 2) {
                tokenProcess.stdin.write(`${description || ''}\n`);
                inputsSent++;
            } else if (output.includes('Enter Website URL') && inputsSent === 3) {
                tokenProcess.stdin.write(`${website || ''}\n`);
                inputsSent++;
            } else if (output.includes('Enter Twitter Handle') && inputsSent === 4) {
                tokenProcess.stdin.write(`${twitter || ''}\n`);
                inputsSent++;
            } else if (output.includes('Enter Token Logo URL') && inputsSent === 5) {
                tokenProcess.stdin.write(`${finalLogoUrl || ''}\n`);
                inputsSent++;
            } else if (output.includes('Proceed with token creation? (yes/no)') && inputsSent === 6) {
                tokenProcess.stdin.write(`yes\n`);
                inputsSent++;
            }
            
            // Update status based on output
            if (output.includes('Connected to:')) {
                res.write(`data: ${JSON.stringify({ step: 1, status: 'success' })}\n\n`);
            }
            
            if (output.includes('Uploading metadata to IPFS')) {
                res.write(`data: ${JSON.stringify({ step: 2, status: 'active' })}\n\n`);
            }
            
            if (output.includes('✓ Metadata uploaded successfully!')) {
                res.write(`data: ${JSON.stringify({ step: 2, status: 'success' })}\n\n`);
                res.write(`data: ${JSON.stringify({ step: 3, status: 'active' })}\n\n`);
            }
            
            if (output.includes('✓ Mint created')) {
                res.write(`data: ${JSON.stringify({ step: 3, status: 'success' })}\n\n`);
                res.write(`data: ${JSON.stringify({ step: 4, status: 'active' })}\n\n`);
            }
            
            if (output.includes('✓ Metadata initialized')) {
                res.write(`data: ${JSON.stringify({ step: 4, status: 'success' })}\n\n`);
                res.write(`data: ${JSON.stringify({ step: 5, status: 'active' })}\n\n`);
            }
            
            if (output.includes('✓ Tokens minted')) {
                res.write(`data: ${JSON.stringify({ step: 5, status: 'success' })}\n\n`);
                res.write(`data: ${JSON.stringify({ step: 6, status: 'active' })}\n\n`);
            }
            
            if (output.includes('✓ Mint authority disabled')) {
                res.write(`data: ${JSON.stringify({ step: 6, status: 'success' })}\n\n`);
            }
            
            // Extract token info from output (sanitized)
            const mintMatch = output.match(/Token Mint: ([\w]+)/);
            if (mintMatch && /^[A-Za-z0-9]+$/.test(mintMatch[1])) {
                tokenInfo.mint = mintMatch[1];
            }
            
            const nameMatch = output.match(/Token Name: (.+)/);
            if (nameMatch) tokenInfo.name = nameMatch[1].trim().substring(0, 50);
            
            const symbolMatch = output.match(/Token Symbol: (.+)/);
            if (symbolMatch) tokenInfo.symbol = symbolMatch[1].trim().substring(0, 10);
            
            const metadataMatch = output.match(/Metadata URI \(IPFS\): (.+)/);
            if (metadataMatch) tokenInfo.metadataUri = metadataMatch[1].trim().substring(0, 500);
            
            const logoMatch = output.match(/Logo URL: (.+)/);
            if (logoMatch) tokenInfo.logoUrl = logoMatch[1].trim().substring(0, 500);
            
            const accountMatch = output.match(/Token Account: ([\w]+)/);
            if (accountMatch && /^[A-Za-z0-9]+$/.test(accountMatch[1])) {
                tokenInfo.tokenAccount = accountMatch[1];
            }
            
            // Check if complete
            if (output.includes('All operations completed successfully!')) {
                clearTimeout(processTimeout);
                console.log(`[${new Date().toISOString()}] Token creation completed:`, tokenInfo.mint);
                res.write(`data: ${JSON.stringify({ complete: true, tokenInfo })}\n\n`);
                setTimeout(() => res.end(), 100);
            }
        });
        
        tokenProcess.stderr.on('data', (data) => {
            const errorMsg = data.toString().substring(0, 200);
            console.error('[Process Error]:', errorMsg);
            res.write(`data: ${JSON.stringify({ error: 'Process error occurred' })}\n\n`);
        });
        
        tokenProcess.on('error', (error) => {
            clearTimeout(processTimeout);
            console.error('[Process Failed]:', error.message);
            res.write(`data: ${JSON.stringify({ error: 'Failed to start token creation process' })}\n\n`);
            res.end();
        });
        
        tokenProcess.on('close', (code) => {
            clearTimeout(processTimeout);
            console.log(`[${new Date().toISOString()}] Process exited with code ${code}`);
            if (code !== 0) {
                res.write(`data: ${JSON.stringify({ error: 'Process failed' })}\n\n`);
            }
            res.end();
        });
        
    } catch (error) {
        console.error('[Server Error]:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('[Error]:', err);
    res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3001;
const HOST = process.env.NODE_ENV === 'production' ? '0.0.0.0' : '127.0.0.1';

const server = app.listen(PORT, HOST, () => {
    const serverUrl = process.env.NODE_ENV === 'production' 
        ? `https://your-backend.railway.app` 
        : `http://localhost:${PORT}`;
    
    console.log(`[${new Date().toISOString()}] Launchium server running on ${serverUrl}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Host: ${HOST}:${PORT}`);
    if (process.env.NODE_ENV !== 'production') {
        console.log(`Frontend: http://localhost:${PORT}`);
    }
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, closing server...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received, closing server...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});
