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

async function uploadJSONToIPFS(jsonData) {
  try {
    console.log("Uploading metadata to IPFS via Pinata...");
    
    if (!PINATA_API_KEY || !PINATA_SECRET_KEY) {
      throw new Error("Pinata credentials not configured");
    }
    
    const formData = new FormData();
    const jsonString = JSON.stringify(jsonData);
    
    formData.append('file', Buffer.from(jsonString), {
      filename: 'metadata.json',
      contentType: 'application/json',
    });
    
    formData.append('pinataOptions', JSON.stringify({
      cidVersion: 1
    }));
    
    formData.append('pinataMetadata', JSON.stringify({
      name: `Token Metadata - ${jsonData.name}`,
      keyvalues: {
        token: jsonData.symbol,
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
          'pinata_api_key': PINATA_API_KEY,
          'pinata_secret_api_key': PINATA_SECRET_KEY
        },
        timeout: 30000
      }
    );
    
    // Use Pinata's gateway for better reliability
    const ipfsUrl = `https://gateway.pinata.cloud/ipfs/${response.data.IpfsHash}`;
    console.log("✓ Metadata uploaded successfully!");
    console.log("  IPFS URL:", ipfsUrl);
    console.log("  IPFS Hash:", response.data.IpfsHash);
    return ipfsUrl;
    
  } catch (error) {
    console.error("Failed to upload to IPFS:", error.response?.data || error.message);
    console.log("Using fallback metadata URL...");
    return `https://launchium.app/api/metadata/default.json`;
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
    
    console.log("\nPreparing metadata...");
    
    const metadataJson = {
      name: tokenDetails.name,
      symbol: tokenDetails.symbol,
      description: tokenDetails.description,
      image: tokenDetails.logoUrl,
      external_url: tokenDetails.website,
      animation_url: "",
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
            type: "image/png"
          }
        ]
      },
      collection: {
        name: "Launchium Tokens",
        family: "Launchium"
      }
    };
    
    const metadataUri = await uploadJSONToIPFS(metadataJson);
    
    // Validate metadata is accessible
    console.log("\nValidating metadata accessibility...");
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
    
    const mintKeypair = Keypair.generate();
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
    
    console.log("\n[Launchium Token Authority] Step 1/5: Creating mint account...");
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
    
    console.log("\n[Launchium Token Authority] Step 2/5: Initializing metadata...");
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
    
    console.log("\n[Launchium Token Authority] Step 3/5: Creating token account...");
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
    
    console.log("\n[Launchium Token Authority] Step 4/5: Minting 1,000,000,000 tokens...");
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
    
    console.log("\n[Launchium Token Authority] Step 5/5: Disabling mint authority...");
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
