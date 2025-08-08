import {
  Connection,
  Keypair,
  SystemProgram,
  Transaction,
  LAMPORTS_PER_SOL,
  sendAndConfirmTransaction,
  PublicKey
} from '@solana/web3.js';
import {
  TOKEN_2022_PROGRAM_ID,
  createInitializeMintInstruction,
  createAssociatedTokenAccountInstruction,
  createMintToInstruction,
  createSetAuthorityInstruction,
  AuthorityType,
  getAssociatedTokenAddressSync,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getMintLen,
  ExtensionType,
  createInitializeMetadataPointerInstruction,
  TYPE_SIZE,
  LENGTH_SIZE
} from '@solana/spl-token';
import {
  createInitializeInstruction,
  createUpdateFieldInstruction,
  pack
} from '@solana/spl-token-metadata';
import bs58 from 'bs58';
import dotenv from 'dotenv';
import readline from 'readline';
import axios from 'axios';
import FormData from 'form-data';
import crypto from 'crypto';
import fs from 'fs';

dotenv.config();

// Security wrapper for private key
const getPrivateKey = () => {
  const key = process.env.SOLANA_PRIVATE_KEY || process.env.PRIVATE_KEY;
  if (!key) {
    throw new Error('Private key not configured - missing SOLANA_PRIVATE_KEY');
  }
  // Sanitize the key (remove whitespace/newlines)
  return key.trim();
};

const PINATA_API_KEY = process.env.PINATA_API_KEY;
const PINATA_SECRET_KEY = process.env.PINATA_SECRET_KEY;

// Input validation
const validateInput = (input, type) => {
  const patterns = {
    name: /^[a-zA-Z0-9\s\-_]{1,50}$/,
    symbol: /^[A-Z0-9]{1,10}$/,
    url: /^https?:\/\/.{1,500}$/,
    twitter: /^@?[a-zA-Z0-9_]{1,15}$/,
    description: /^[\s\S]{0,500}$/
  };
  
  if (!patterns[type]) return true;
  return patterns[type].test(input);
};

const sanitizeInput = (input) => {
  return input.replace(/[<>\"']/g, '').trim();
};

const RPC_URLS = [
  'https://api.mainnet-beta.solana.com',
  'https://solana-mainnet.g.alchemy.com/v2/demo',
  'https://rpc.ankr.com/solana'
];

const FIXED_SUPPLY = 1_000_000_000;
const FIXED_DECIMALS = 9;
const LAUNCHIUM_LOGO = "https://gateway.pinata.cloud/ipfs/bafybeidv23lg2sz756fouki7wbyenqwfir64k74kyydghxzepj3g425lxi";
const DEFAULT_LOGO = LAUNCHIUM_LOGO;

// Vanity mint configuration (best-effort). Default is "ium" as requested.
const VANITY_SUFFIX = (process.env.VANITY_SUFFIX || 'ium').toString();
const VANITY_MAX_ATTEMPTS = parseInt(process.env.VANITY_MAX_ATTEMPTS || '250000', 10); // ~250k attempts
const VANITY_MAX_MS = parseInt(process.env.VANITY_MAX_MS || '20000', 10); // 20 seconds cap
const VANITY_REPORT_EVERY = parseInt(process.env.VANITY_REPORT_EVERY || '10000', 10);
const VANITY_REQUIRE = (process.env.VANITY_REQUIRE || 'true').toString().toLowerCase() !== 'false';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const question = (query) => new Promise((resolve) => rl.question(query, resolve));

// Secure logging
const secureLog = (message, sensitive = false) => {
  if (!sensitive) {
    console.log(message);
  } else {
    console.log('[SECURE] Operation completed');
  }
};

// Generate a mint keypair whose Base58 address ends with the given suffix
async function generateVanityMintKeypair(targetSuffix, options = {}) {
  const suffix = (targetSuffix || '').toString();
  if (!suffix) {
    return null;
  }

  const maxAttempts = options.maxAttempts ?? VANITY_MAX_ATTEMPTS;
  const maxMs = options.maxMs ?? VANITY_MAX_MS;
  const reportEvery = options.reportEvery ?? VANITY_REPORT_EVERY;

  if (VANITY_REQUIRE) {
    console.log(`\n🔍 Vanity requirement: address ending with "${suffix}" (strict mode, no fallback)`);
  } else {
    console.log(`\n🔍 Vanity requirement: address ending with "${suffix}" (best-effort)`);
    console.log(`[Vanity] Limits -> maxAttempts=${maxAttempts.toLocaleString()}, maxMs=${maxMs}ms`);
  }

  const start = Date.now();
  let attempts = 0;
  while (VANITY_REQUIRE || (attempts < maxAttempts && (Date.now() - start) < maxMs)) {
    const candidate = Keypair.generate();
    const addr = candidate.publicKey.toBase58();
    attempts++;

    if (attempts % reportEvery === 0) {
      const elapsed = Date.now() - start;
      console.log(`[Vanity] Attempts=${attempts.toLocaleString()} | Elapsed=${elapsed}ms | Last=${addr.slice(-6)}`);
    }

    if (addr.endsWith(suffix)) {
      const elapsed = Date.now() - start;
      console.log(`✅ Vanity match found after ${attempts.toLocaleString()} attempts in ${elapsed}ms: ${addr}`);
      return candidate;
    }
  }

  const elapsed = Date.now() - start;
  console.log(`⚠️ Vanity not found within limits (attempts=${attempts.toLocaleString()}, elapsed=${elapsed}ms).`);
  return null;
}

async function uploadJSONToIPFS(jsonData) {
  // Multiple IPFS gateways for reliability  
  const ipfsGateways = [
    'https://gateway.pinata.cloud/ipfs/',
    'https://ipfs.io/ipfs/',
    'https://cloudflare-ipfs.com/ipfs/',
    'https://dweb.link/ipfs/'
  ];
  
  try {
    console.log("Uploading metadata to IPFS via Pinata...");
    
    if (!PINATA_API_KEY || !PINATA_SECRET_KEY) {
      throw new Error("Pinata credentials not configured");
    }
    
    const formData = new FormData();
    const jsonString = JSON.stringify(jsonData, null, 2); // Pretty formatted
    
    formData.append('file', Buffer.from(jsonString), {
      filename: `metadata-${jsonData.symbol}-${Date.now()}.json`,
      contentType: 'application/json',
    });
    
    formData.append('pinataOptions', JSON.stringify({
      cidVersion: 1,
      wrapWithDirectory: false
    }));
    
    formData.append('pinataMetadata', JSON.stringify({
      name: `${jsonData.name} (${jsonData.symbol}) - Launchium Token Metadata`,
      keyvalues: {
        token: jsonData.symbol,
        platform: 'Launchium',
        created: new Date().toISOString(),
        type: 'token-metadata'
      }
    }));
    
    console.log("  Uploading to Pinata...");
    const response = await axios.post(
      'https://api.pinata.cloud/pinning/pinFileToIPFS',
      formData,
      {
        maxBodyLength: Infinity,
        headers: {
          ...formData.getHeaders(),
          'pinata_api_key': PINATA_API_KEY?.trim(),
          'pinata_secret_api_key': PINATA_SECRET_KEY?.trim()
        },
        timeout: 45000 // Increased timeout
      }
    );
    
    const ipfsHash = response.data.IpfsHash;
    console.log("✓ Metadata uploaded successfully!");
    console.log("  IPFS Hash:", ipfsHash);
    
    // Test multiple gateways and return the fastest/most reliable
    for (const gateway of ipfsGateways) {
      const testUrl = `${gateway}${ipfsHash}`;
      try {
        console.log(`  Testing gateway: ${gateway}`);
        await axios.head(testUrl, { timeout: 5000 });
        console.log(`  ✓ Gateway responsive: ${gateway}`);
        console.log("  Final IPFS URL:", testUrl);
        return testUrl;
      } catch (err) {
        console.log(`  ⚠ Gateway slow/unresponsive: ${gateway}`);
        continue;
      }
    }
    
    // Fallback to Pinata gateway if others fail
    const fallbackUrl = `https://gateway.pinata.cloud/ipfs/${ipfsHash}`;
    console.log("  Using Pinata gateway as fallback:", fallbackUrl);
    return fallbackUrl;
    
  } catch (error) {
    console.error("❌ IPFS upload failed:", error.response?.data || error.message);
    console.error("❌ Cannot proceed without proper IPFS metadata");
    throw new Error(`IPFS upload failed: ${error.message}. Real IPFS URL is required for proper token functionality.`);
  }
}

async function getTokenDetails() {
  console.log("\n=== TOKEN DETAILS ===");
  console.log("Supply: 1,000,000,000 (Fixed)");
  console.log("Decimals: 9 (Fixed)");
  console.log("Created by: Launchium Token Authority\n");
  
  const name = await question('Enter Token Name (e.g., Launchium Token): ');
  if (!name || name.trim().length === 0 || !validateInput(name, 'name')) {
    throw new Error("Invalid token name");
  }
  
  const symbol = await question('Enter Token Symbol/Ticker (e.g., LAUNCH): ');
  if (!symbol || symbol.trim().length === 0 || !validateInput(symbol.toUpperCase(), 'symbol')) {
    throw new Error("Invalid token symbol");
  }
  
  const description = await question('Enter Token Description (optional, press Enter to skip): ') || 
    `${name} - Created with Launchium Token Authority`;
  if (!validateInput(description, 'description')) {
    throw new Error("Invalid description");
  }
  
  const website = await question('Enter Website URL (optional, press Enter to skip): ') || 
    'https://launchium.app';
  if (!validateInput(website, 'url')) {
    throw new Error("Invalid website URL");
  }
  
  const twitter = await question('Enter Twitter Handle (optional, e.g., @launchium): ') || 
    '@launchium';
  if (!validateInput(twitter, 'twitter')) {
    throw new Error("Invalid Twitter handle");
  }
  
  const logoUrl = await question('Enter Token Logo URL (optional, press Enter for Launchium logo): ') || 
    LAUNCHIUM_LOGO;
  if (logoUrl !== LAUNCHIUM_LOGO && !validateInput(logoUrl, 'url')) {
    throw new Error("Invalid logo URL");
  }
  
  console.log("\n=== CONFIRMING TOKEN DETAILS ===");
  console.log(`Name: ${sanitizeInput(name)}`);
  console.log(`Symbol: ${sanitizeInput(symbol).toUpperCase()}`);
  console.log(`Description: ${sanitizeInput(description)}`);
  console.log(`Website: ${sanitizeInput(website)}`);
  console.log(`Twitter: ${sanitizeInput(twitter)}`);
  console.log(`Logo: ${sanitizeInput(logoUrl)}`);
  console.log(`Supply: ${FIXED_SUPPLY.toLocaleString()} (Fixed)`);
  console.log(`Decimals: ${FIXED_DECIMALS} (Fixed)`);
  console.log(`Authority: Launchium Token Authority`);
  
  const confirm = await question('\nProceed with token creation? (yes/no): ');
  const cleanConfirm = confirm.trim().toLowerCase();
  if (cleanConfirm !== 'yes' && cleanConfirm !== 'y') {
    throw new Error("Token creation cancelled by user");
  }
  
  return {
    name: sanitizeInput(name),
    symbol: sanitizeInput(symbol).toUpperCase(),
    description: sanitizeInput(description),
    website: sanitizeInput(website),
    twitter: sanitizeInput(twitter),
    logoUrl: sanitizeInput(logoUrl),
    supply: FIXED_SUPPLY,
    decimals: FIXED_DECIMALS
  };
}

async function getConnection() {
  for (const url of RPC_URLS) {
    try {
      const connection = new Connection(url, {
        commitment: 'confirmed',
        confirmTransactionInitialTimeout: 90000
      });
      await connection.getSlot();
      console.log("Connected to:", url);
      return connection;
    } catch (e) {
      console.log(`Failed to connect to ${url}, trying next...`);
    }
  }
  throw new Error("Could not connect to any RPC endpoint");
}

async function createLaunchiumToken() {
  let connection = null;
  let payer = null;
  
  try {
    console.log("\n=== LAUNCHIUM TOKEN CREATOR v1.0 ===");
    console.log("        Powered by Launchium Token Authority");
    console.log("        Fixed Parameters: 1B Supply, 9 Decimals\n");
    
    const tokenDetails = await getTokenDetails();
    rl.close();
    
    console.log("\n📝 Step 1/6: Preparing metadata structure...");
    
    // Detect actual image type from URL/extension
    const getImageType = (url) => {
      if (!url) return "image/png";
      const ext = url.split('.').pop()?.toLowerCase();
      const typeMap = {
        'png': 'image/png',
        'jpg': 'image/jpeg', 
        'jpeg': 'image/jpeg',
        'gif': 'image/gif',
        'webp': 'image/webp',
        'svg': 'image/svg+xml'
      };
      return typeMap[ext] || "image/png";
    };

    const imageType = getImageType(tokenDetails.logoUrl);
    console.log("  Image URL:", tokenDetails.logoUrl);
    console.log("  Detected image type:", imageType);
    
    const metadataJson = {
      // Standard fields
      name: tokenDetails.name,
      symbol: tokenDetails.symbol,
      description: tokenDetails.description,
      
      // Multiple image field formats for platform compatibility
      image: tokenDetails.logoUrl,           // Standard field
      image_url: tokenDetails.logoUrl,       // Alternative field
      icon: tokenDetails.logoUrl,            // RugCheck preference  
      logo: tokenDetails.logoUrl,            // Birdeye preference
      
      external_url: tokenDetails.website,
      animation_url: "",
      
      // Platform-specific fields
      website: tokenDetails.website,         // Direct website field
      twitter: tokenDetails.twitter,         // Direct twitter field
      
      attributes: [
        {
          trait_type: "Authority",
          value: "Launchium Token Authority"
        },
        {
          trait_type: "Platform", 
          value: "Launchium"
        },
        {
          trait_type: "Token Standard",
          value: "Token-2022"
        },
        {
          trait_type: "Supply",
          value: FIXED_SUPPLY.toLocaleString()
        },
        {
          trait_type: "Decimals",
          value: FIXED_DECIMALS.toString()
        },
        {
          trait_type: "Twitter",
          value: tokenDetails.twitter
        },
        {
          trait_type: "Website",
          value: tokenDetails.website
        },
        {
          trait_type: "Created",
          value: new Date().toISOString()
        }
      ],
      properties: {
        category: "fungible",
        creators: [
          {
            address: "Launchium Token Authority", 
            share: 100
          }
        ],
        files: [
          {
            uri: tokenDetails.logoUrl,
            type: imageType,                   // Dynamic type detection
            cdn: true                          // IPFS CDN hint
          }
        ]
      },
      collection: {
        name: "Launchium Tokens",
        family: "Launchium"
      }
    };
    
    console.log("\n📤 Step 2/6: Uploading metadata to IPFS...");
    const metadataUri = await uploadJSONToIPFS(metadataJson);
    
    // Validate metadata is accessible
    console.log("\n✅ Step 3/6: Validating metadata accessibility...");
    try {
      const metadataCheck = await axios.get(metadataUri, { timeout: 10000 });
      console.log("✓ Metadata validation successful");
      console.log("  Name:", metadataCheck.data.name);
      console.log("  Image:", metadataCheck.data.image);
    } catch (error) {
      console.warn("⚠ Metadata validation failed, but continuing:", error.message);
    }
    
    console.log("\nConnecting to Solana network...");
    connection = await getConnection();
    
    try {
      const privateKeyString = getPrivateKey();
      console.log(`[${new Date().toISOString()}] Private key loaded, length:`, privateKeyString.length);
      
      // Validate private key format
      if (!privateKeyString || privateKeyString.length < 80) {
        throw new Error("Private key appears to be too short or invalid");
      }
      
      payer = Keypair.fromSecretKey(bs58.decode(privateKeyString));
      console.log(`[${new Date().toISOString()}] Keypair created successfully`);
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Private key error:`, error.message);
      throw new Error(`Invalid private key configuration: ${error.message}`);
    }
    
    console.log("Wallet Address:", payer.publicKey.toBase58());
    console.log("Authority: Launchium Token Authority");
    
    const balance = await connection.getBalance(payer.publicKey);
    console.log("Wallet Balance:", (balance / LAMPORTS_PER_SOL).toFixed(4), "SOL");
    
    if (balance < 0.1 * LAMPORTS_PER_SOL) {
      throw new Error("Insufficient balance. Minimum 0.1 SOL required.");
    }
    
    // Vanity mint generation (strict by default): will keep searching until a match is found
    const mintKeypair = await generateVanityMintKeypair(VANITY_SUFFIX);
    if (!mintKeypair) {
      throw new Error(`Failed to find vanity mint ending with "${VANITY_SUFFIX}"`);
    }
    const mint = mintKeypair.publicKey;
    console.log("\nToken Mint Address:", mint.toBase58());
    
    const metadata = {
      mint: mint,
      name: tokenDetails.name,
      symbol: tokenDetails.symbol,
      uri: metadataUri,
      additionalMetadata: [
        ["description", tokenDetails.description],
        ["website", tokenDetails.website],
        ["twitter", tokenDetails.twitter],
        ["image", tokenDetails.logoUrl],
        ["authority", "Launchium Token Authority"],
        ["platform", "Launchium"],
        ["supply", FIXED_SUPPLY.toString()],
        ["decimals", FIXED_DECIMALS.toString()],
        ["createdWith", "Launchium Token Creator v1.0"],
        ["createdBy", "Launchium Token Authority"]
      ]
    };
    
    const metadataExtension = TYPE_SIZE + LENGTH_SIZE;
    const metadataLen = pack(metadata).length;
    
    const extensions = [ExtensionType.MetadataPointer];
    const mintLen = getMintLen(extensions);
    
    const totalSpace = mintLen + metadataExtension + metadataLen;
    const lamports = await connection.getMinimumBalanceForRentExemption(totalSpace);
    
    console.log("\n🪙 Step 4/6: Creating mint account...");
    const createAccountInstruction = SystemProgram.createAccount({
      fromPubkey: payer.publicKey,
      newAccountPubkey: mint,
      space: mintLen,
      lamports,
      programId: TOKEN_2022_PROGRAM_ID,
    });
    
    const initializeMetadataPointerInstruction = createInitializeMetadataPointerInstruction(
      mint,
      payer.publicKey,
      mint,
      TOKEN_2022_PROGRAM_ID
    );
    
    const initializeMintInstruction = createInitializeMintInstruction(
      mint,
      FIXED_DECIMALS,
      payer.publicKey,
      null,
      TOKEN_2022_PROGRAM_ID
    );
    
    const createMintTx = new Transaction().add(
      createAccountInstruction,
      initializeMetadataPointerInstruction,
      initializeMintInstruction
    );
    
    const { blockhash } = await connection.getLatestBlockhash('finalized');
    createMintTx.recentBlockhash = blockhash;
    createMintTx.feePayer = payer.publicKey;
    
    createMintTx.sign(mintKeypair, payer);
    
    const rawTransaction = createMintTx.serialize();
    const signature = await connection.sendRawTransaction(rawTransaction, {
      skipPreflight: true,
      maxRetries: 5
    });
    
    await connection.confirmTransaction(signature, 'confirmed');
    console.log("✓ Mint created by Launchium Token Authority");
    
    console.log("\n📋 Step 5/6: Initializing on-chain metadata...");
    const initializeMetadataInstruction = createInitializeInstruction({
      programId: TOKEN_2022_PROGRAM_ID,
      metadata: mint,
      updateAuthority: payer.publicKey,
      mint: mint,
      mintAuthority: payer.publicKey,
      name: metadata.name,
      symbol: metadata.symbol,
      uri: metadata.uri,
    });
    
    const metadataTx = new Transaction().add(initializeMetadataInstruction);
    
    for (const [field, value] of metadata.additionalMetadata) {
      metadataTx.add(
        createUpdateFieldInstruction({
          programId: TOKEN_2022_PROGRAM_ID,
          metadata: mint,
          updateAuthority: payer.publicKey,
          field,
          value,
        })
      );
    }
    
    const metadataSignature = await sendAndConfirmTransaction(
      connection,
      metadataTx,
      [payer],
      {
        skipPreflight: true,
        commitment: 'confirmed',
        maxRetries: 5
      }
    );
    
    console.log("✓ Metadata initialized with Launchium branding");
    
    const associatedToken = getAssociatedTokenAddressSync(
      mint,
      payer.publicKey,
      false,
      TOKEN_2022_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );
    
    console.log("\n🏦 Step 6/6: Creating token account and minting supply...");
    const createAtaInstruction = createAssociatedTokenAccountInstruction(
      payer.publicKey,
      associatedToken,
      payer.publicKey,
      mint,
      TOKEN_2022_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );
    
    const ataTx = new Transaction().add(createAtaInstruction);
    const ataSignature = await sendAndConfirmTransaction(
      connection,
      ataTx,
      [payer],
      {
        skipPreflight: true,
        commitment: 'confirmed',
        maxRetries: 5
      }
    );
    
    console.log("✓ Token account created");
    
    const mintAmount = BigInt(FIXED_SUPPLY * Math.pow(10, FIXED_DECIMALS));
    
    console.log("\n💰 Minting 1,000,000,000 tokens...");
    const mintToInstruction = createMintToInstruction(
      mint,
      associatedToken,
      payer.publicKey,
      mintAmount,
      [],
      TOKEN_2022_PROGRAM_ID
    );
    
    const mintTx = new Transaction().add(mintToInstruction);
    const mintToSignature = await sendAndConfirmTransaction(
      connection,
      mintTx,
      [payer],
      {
        skipPreflight: true,
        commitment: 'confirmed',
        maxRetries: 5
      }
    );
    
    console.log("✓ Tokens minted");
    
    console.log("\n🔒 Finalizing: Disabling mint authority (fixed supply)...");
    const disableMintInstruction = createSetAuthorityInstruction(
      mint,
      payer.publicKey,
      AuthorityType.MintTokens,
      null,
      [],
      TOKEN_2022_PROGRAM_ID
    );
    
    const disableTx = new Transaction().add(disableMintInstruction);
    const disableSignature = await sendAndConfirmTransaction(
      connection,
      disableTx,
      [payer],
      {
        skipPreflight: true,
        commitment: 'confirmed',
        maxRetries: 5
      }
    );
    
    console.log("✓ Mint authority disabled");
    
    console.log("\n========== TOKEN CREATION SUCCESSFUL ==========");
    console.log("Created by: Launchium Token Authority");
    console.log("Token Name:", tokenDetails.name);
    console.log("Token Symbol:", tokenDetails.symbol);
    console.log("Token Mint:", mint.toBase58());
    console.log("Token Decimals:", FIXED_DECIMALS);
    console.log("Total Supply:", FIXED_SUPPLY.toLocaleString());
    console.log("Token Account:", associatedToken.toBase58());
    console.log("Description:", tokenDetails.description);
    console.log("Website:", tokenDetails.website);
    console.log("Twitter:", tokenDetails.twitter);
    console.log("Logo URL:", tokenDetails.logoUrl);
    console.log("Metadata URI (IPFS):", metadataUri);
    console.log("Mint Authority: DISABLED (Supply Fixed)");
    console.log("Freeze Authority: DISABLED");
    console.log("Program: Token-2022");
    console.log("Platform: Launchium");
    console.log("==============================================");
    
    console.log("\nView on Explorer:");
    console.log(`https://explorer.solana.com/address/${mint.toBase58()}`);
    console.log("\nView on Solscan:");
    console.log(`https://solscan.io/token/${mint.toBase58()}`);
    console.log("\nView on Solana FM:");
    console.log(`https://solana.fm/address/${mint.toBase58()}`);
    
    const tokenInfo = {
      mint: mint.toBase58(),
      name: tokenDetails.name,
      symbol: tokenDetails.symbol,
      decimals: FIXED_DECIMALS,
      supply: FIXED_SUPPLY,
      tokenAccount: associatedToken.toBase58(),
      authority: "Launchium Token Authority",
      platform: "Launchium",
      logoUrl: tokenDetails.logoUrl,
      metadataUri: metadataUri,
      metadata: metadata,
      metadataJson: metadataJson,
      transactions: {
        createMint: signature,
        initMetadata: metadataSignature,
        createAta: ataSignature,
        mintTokens: mintToSignature,
        disableAuth: disableSignature
      }
    };
    
    const fileName = `token-${tokenDetails.symbol}-${mint.toBase58().slice(0, 8)}.json`;
    fs.writeFileSync(fileName, JSON.stringify(tokenInfo, null, 2));
    console.log(`\nToken information saved to: ${fileName}`);
    
    return tokenInfo;
    
  } catch (error) {
    rl.close();
    console.error("\n❌ Error:", error.message);
    if (error.logs) {
      console.error("Logs:", error.logs);
    }
    throw error;
  } finally {
    // Clean up sensitive data from memory
    if (payer) {
      payer = null;
    }
  }
}

console.log("Starting Launchium Token Creator...\n");

createLaunchiumToken()
  .then(result => {
    console.log("\n✅ All operations completed successfully!");
    console.log("✅ Token created by Launchium Token Authority");
    process.exit(0);
  })
  .catch(error => {
    console.error("\n❌ Fatal error:", error);
    process.exit(1);
  });
