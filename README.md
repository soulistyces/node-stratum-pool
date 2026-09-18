# High Performance SHA256 Stratum Pool Server

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

High performance Stratum poolserver with enhanced SHA256 support in Node.js. One instance of this software can startup and manage multiple coin pools, each with their own daemon and stratum port :)

## 🚀 New Features in This Fork

### AsicBoost Support with Version Rolling

- **Full AsicBoost compatibility** for modern SHA256 ASIC miners
- **Version rolling** (BIP320) support for improved mining efficiency
- Automatic detection and negotiation of version rolling mask
- Compatible with all major ASIC manufacturers (Bitmain, MicroBT, Canaan, etc.)

### Solo Mining Mode

- Complete solo mining functionality
- Direct block rewards to miner addresses
- Real-time solo mining statistics

### Enhanced PROP Payout Mode

- **Fixed and properly implemented** proportional payout system
- Accurate share tracking and reward distribution
- Improved round management
- Fair distribution based on actual work contributed

---

## Notice

This is a module for Node.js that will do nothing on its own. Unless you're a Node.js developer who would like to handle stratum authentication and raw share data then this module will not be of use to you. For a full featured portal that uses this module, see [s-nomp (Some New Open Mining Portal)](https://github.com/s-nomp/s-nomp). It handles payments, website front-end, database layer, mutli-coin/pool support, auto-switching miners between coins/pools, etc.. The portal also has an [MPOS](https://github.com/MPOS/php-mpos) compatibility mode so that the it can function as a drop-in-replacement for [python-stratum-mining](https://github.com/Crypto-Expert/stratum-mining).

[![NPM](https://nodei.co/npm/stratum-pool.png?downloads=true&stars=true)](https://nodei.co/npm/stratum-pool/)

## Why

This server was built to be more efficient and easier to setup, maintain and scale than existing stratum poolservers which are written in python. Compared to the spaghetti state of the latest [stratum-mining python server](https://github.com/Crypto-Expert/stratum-mining/), this software should also have a lower barrier to entry for other developers to fork and add features or fix bugs.

## Features

### Core Features

- Daemon RPC interface
- Stratum TCP socket server
- Block template / job manager
- P2P to get block notifications as peer node
- Optimized generation transaction building
- Connecting to multiple daemons for redundancy
- Process share submissions
- Session managing for purging DDoS/flood initiated zombie workers
- Auto ban IPs that are flooding with invalid shares
- **POW** (proof-of-work) & **POS** (proof-of-stake) support
- Transaction messages support
- Vardiff (variable difficulty / share limiter)
- When started with a coin daemon that hasn't finished syncing to the network it shows the blockchain download progress and initializes once synced

### Enhanced SHA256 Features (New)

- ✓ **AsicBoost Support** - Overt AsicBoost with version rolling
- ✓ **Version Rolling (BIP320)** - Efficient nonce space distribution
- ✓ **Multi-Version Support** - `mining.multi_version` extension for overt AsicBoost
- ✓ **Solo Mining Mode** - Direct mining without pool shares
- ✓ **Proper PROP Implementation** - Fair proportional reward distribution
- ✓ **Advanced Security Module** - Comprehensive DDoS protection and rate limiting

### Hashing Algorithms Supported

- ✓ **SHA256** (Bitcoin, Bitcoin Cash, etc.)
- ✓ **SHA256 with AsicBoost**

## Requirements

- node v8.11+
- coin daemon (preferably one with a relatively updated API)

## Installation

### Install as a node module by cloning repository

```bash
git clone https://github.com/janos-raul/node-stratum-pool.git node_modules/stratum-pool
npm update
```

## Configuration

### Basic Coin Configuration

```javascript
var myCoin = {
{
  "name": "bitcoin",
  "symbol": "BTC",
  "algorithm": "sha256",
  "reward": "POW",
  "asicboost": true,
  "versionMask": "0x3fffe000",
  "enforcePoolVersionMask": true,
  "versionRollingMinBits": 16,
  "asicboostMinDifficulty": 1000,
  "asicboostMaxClients": 1000,
  "multiVersion": {
    "enabled": true,
    "maxVersions": 4,
    "generationMode": "sequential"
  },
  "coinbasePayouts": {
    "enabled": false,
    "coinbaseOnly": false,
    "feeHandledInCoinbase": false
  },
  "txMessages": true,                   // Enables the pool signature OP_RETURN output
  "txMessageText": "",                  // Custom OP_RETURN text (max 255 bytes, truncated if longer);
                                         // falls back to a built-in default if left empty
  "segwit": true,
  "default_witness_commitment": true,   // Informational only — witness commitment is included
                                         // automatically whenever the daemon's GBT response provides
                                         // one; this flag is not read anywhere and does not gate it
  "blockTime": 300,                     // Used for luck (luckDays/luckHours/luckMinute) calculations
  "minConf": 101,                       // Informational/reference only — the value that actually
                                         // gates payouts is the pool config's paymentProcessing.minConf

"addressValidation": {
		"validateWorkerUsername": true,
		"addressPrefix": "bc1",
		"minLength": 30,
		"maxLength": 42
  },

"explorer": {
        "txURL": "https://bitcoinexplorer.org/tx/",
        "blockURL": "https://bitcoinexplorer.org/block/"
    },

"rpc": {
            "host": "127.0.0.1",
            "port": 8332,
            "user": "bitcoinrpc",
            "password": "password"
  }
}
```

### Pool Configuration with New Features

```javascript
var Stratum = require('stratum-pool');

var pool = Stratum.createPool({

{
    // Basic settings
    "enabled": true,                     // Enable this pool
    "coin": "bitcoin.json",              // Reference to coin config file
    "asicboost": true,                   // Enable ASICBoost for this pool
    "blockIdentifier": "",               // Text embedded in the coinbase scriptSig, wrapped in slashes
                                          // (e.g. "mypool.com" -> "/mypool.com/"). Threaded per-coin all
                                          // the way through transaction building, so different coins in
                                          // the same process can safely use different values. Truncated
                                          // at 64 bytes to stay within the scriptSig's 100-byte consensus
                                          // limit. Falls back to a built-in default if left empty.

	  // ============================================================================
	  // SECURITY MODULE - Advanced DDoS Protection & Rate Limiting
	  // ============================================================================

	  "security": {
		"enabled": true,                    // Master switch for security features

		// Rate Limiting Configuration
		// Tracks and limits connection attempts, malformed messages, and floods per IP
		"rateLimit": {
		  "enabled": true,                  // Enable rate limiting
		  "window": 60000,                  // Time window in ms (60000 = 1 minute)
		  "maxConnections": 10,             // Max connections per IP per window
		  "maxMalformed": 3,                // Max malformed messages before ban
		  "maxFloods": 2                    // Max socket flood detections before ban
		},

		// Auto-Ban System Configuration
		// Progressive ban system with escalating durations based on strikes
		"ban": {
		  "enabled": true,                  // Enable automatic IP banning
		  "duration": 600000,               // Initial ban duration in ms (600000 = 10 minutes)
		  "maxStrikes": 3,                  // Number of strikes before permanent ban
		  "permanentDuration": 86400000     // Permanent ban duration in ms (86400000 = 24 hours)
		}
	  },

    // Pool wallet and fee addresses
    "address": "YOUR_POOL_WALLET_ADDRESS",    // Main pool payout address

    "rewardRecipients": {
        // IMPORTANT: This is a COINBASE-LEVEL split, deducted BEFORE poolFee/soloFee!
        // If you set this > 0, it reduces the block reward available for fee calculation
        // Example: 6.25 BTC block with 1.0% here = 0.0625 BTC to fee address at coinbase
        //          Remaining 6.1875 BTC is then split by poolFee/soloFee percentages
        // RECOMMENDED: Set to 0.0 and use poolFee/soloFee instead for simpler accounting
        "YOUR_FEE_ADDRESS": 0.0          // Coinbase reward split (0.0 = disabled, recommended)
    },

    // Payment processing configuration
    "paymentProcessing": {
        "txfee": 0.0004,                 // Transaction fee for payouts
        "minConf": 101,                  // Confirmations before payment (must match coin config)
        "enabled": true,                 // Enable automatic payments
        "soloMining": true,              // Enable solo mining mode
        "paymentMode": "prop",           // Payment mode: "prop" or "pplnt"
        "poolFee": 2.0,                  // Pool mining fee (2.0 = 2%) - applied AFTER rewardRecipients
        "soloFee": 2.0,                  // Solo mining fee (2.0 = 2%) - applied AFTER rewardRecipients
        "paymentInterval": 3600,         // Payment interval in seconds (3600 = 1 hour)
        "minimumPayment": 0.01,          // Minimum payout for pool miners
        "minimumPayment_solo": 0.01,     // Minimum payout for solo miners
        "maxBlocksPerPayment": 5,        // Maximum blocks to process per payment run

        // Payment daemon connection
        "daemon": {
            "host": "127.0.0.1",
            "port": 8332,
            "user": "rpcuser",
            "password": "rpcpassword"
        }
    },

    // TLS/SSL configuration (optional)
    "tlsOptions": {
        "enabled": false,
        "serverKey": "",
        "serverCert": "",
        "ca": ""
    },

    // Mining ports configuration
    "ports": {
        "50212": {                       // Port number
            "diff": 25000,               // Starting difficulty
            "tls": false,                // Enable TLS for this port
            "soloMining": true,          // Allow solo mining on this port
            "varDiff": {                 // Variable difficulty settings
                "minDiff": 10000,        // Minimum difficulty
                "maxDiff": 500000,       // Maximum difficulty
                "targetTime": 30,        // Target time between shares (seconds)
                "retargetTime": 200,     // How often to adjust difficulty (seconds)
                "variancePercent": 5     // Allowed variance percentage
            }
        },
        "50213": {                       // Higher difficulty port for larger miners
            "diff": 50000,
            "tls": false,
            "soloMining": true,
            "varDiff": {
                "minDiff": 50000,
                "maxDiff": 5000000,
                "targetTime": 35,
                "retargetTime": 240,
                "variancePercent": 5
            }
        }
    },

    // Pool identifier for multi-region setups
    "poolId": "main",

    // Daemon instances for block submission and monitoring
    "daemons": [
        {
            "host": "127.0.0.1",
            "port": 8332,
            "user": "rpcuser",
            "password": "rpcpassword"
        }
    ]
}
```

### Event Handling with New Features

```javascript
// Share event
pool.on('share', function(isValidShare, isValidBlock, data) {
    /*
    data object includes:
        - job: the job ID this share was submitted against
        - ip: submitting miner's IP address
        - worker: full worker name (address.workername)
        - difficulty: the miner's currently assigned difficulty
        - isSoloMining: boolean, true if this worker is solo mining
        - isAsicBoost: boolean, true if the share used AsicBoost version rolling
        - version: the block version used for this share
        - error: present only when isValidShare is false
    */

            if (!isValidBlock)
                emitShare();
            else{
                SubmitBlock(blockHex, function(){

    console.log('Share data:', JSON.stringify(data));
});
```

## Usage Examples

### Basic SHA256 Pool with AsicBoost

```javascript
var bitcoin = {
  name: "bitcoin",
  symbol: "BTC",
  algorithm: "sha256",
  reward: "POW",
  asicboost: true,
  versionMask: "0x3fffe000",
  enforcePoolVersionMask: true,
  versionRollingMinBits: 16,
  asicboostMinDifficulty: 1000,
  asicboostMaxClients: 1000,
  multiVersion: {
    enabled: true,
    maxVersions: 4,
    generationMode: "sequential",
  },
  coinbasePayouts: {
    enabled: false,
    coinbaseOnly: false,
    feeHandledInCoinbase: false,
  },
  txMessages: true, // Enables the pool signature OP_RETURN output
  txMessageText: "", // Custom OP_RETURN text (max 255 bytes); falls back to a
  // built-in default if left empty
  segwit: true,
  default_witness_commitment: true, // Informational only — included automatically whenever the
  // daemon's GBT response provides one, not gated by this flag
  blockTime: 300, // Used for luck calculations
  minConf: 101, // Informational only — real gate is paymentProcessing.minConf
};

// Create pool with AsicBoost enabled
var pool = Stratum.createPool({
  coin: bitcoin,
  address: "bc1qpool...",
  asicboost: true,
  // ... other configuration
});
```

### Solo Mining Setup

```javascript
// Configure solo mining port, solo mining detection is based on user password "m=solo"
"ports": {
    "3334": {
        "diff": 8192,
        "soloMining": true,
        "varDiff": {
            "minDiff": 8192,
            "maxDiff": 1048576,
            "targetTime": 30,
            "retargetTime": 200,
            "variancePercent": 5
        }
    }
}
```

## Stratum Extensions

This implementation supports the following stratum extensions:

- `mining.subscribe` with version rolling support
- `mining.configure` for AsicBoost negotiation
- `mining.multi_version` for overt AsicBoost with multiple versions
- `mining.suggest_difficulty` — miner-requested starting difficulty, honored alongside the pool's own per-port default
- `mining.submit` with version bits

### mining.multi_version Support

The `mining.multi_version` extension allows miners to request multiple block versions simultaneously, enabling overt AsicBoost mining. This is an alternative to `mining.configure` version rolling.

#### How it works:

1. Miner sends: `{"method": "mining.multi_version", "params": [4]}`
2. Pool responds with `result: true` if enabled
3. Pool sends jobs with multiple versions in `mining.notify`
4. Miner can use any of the provided versions for share submission

#### Coin Configuration:

```javascript
{
  "name": "bitcoin",
  "symbol": "BTC",
  "algorithm": "sha256",
  // ... other config ...

  "multiVersion": {
    "enabled": true,        // Enable mining.multi_version support
    "maxVersions": 4,       // Maximum versions a miner can request (1-16)
    "mode": "sequential"    // Version generation mode: "sequential"
  }
}
```

#### Configuration Options:

| Option        | Type    | Default      | Description                                    |
| ------------- | ------- | ------------ | ---------------------------------------------- |
| `enabled`     | boolean | false        | Enable/disable multi_version support           |
| `maxVersions` | number  | 4            | Maximum number of versions a miner can request |
| `mode`        | string  | "sequential" | How versions are generated ("sequential")      |

#### Miner Compatibility:

Miners supporting `mining.multi_version`:

- Custom firmware with multi_version support
- Some Bitmain firmware variants
- Mining proxies with multi_version capability

## Testing

Test your AsicBoost implementation:

```bash
# Test with bfgminer
bfgminer -o stratum+tcp://localhost:3333 -u walletaddress -p x --version-rolling

# Test with cgminer
cgminer -o stratum+tcp://localhost:3333 -u walletaddress -p x
```

## Performance Optimizations

- AsicBoost reduces power consumption by ~20%
- Version rolling improves efficiency for high-hashrate miners
- Optimized share validation for SHA256
- Efficient job distribution for large mining farms

## Security Features

### Advanced Security Module

The stratum pool includes a comprehensive security system designed to protect against various attacks:

#### Features:

- **Rate Limiting**: Tracks connections, malformed messages, and socket floods per IP
- **Progressive Ban System**: Escalating ban durations based on strike count
- **Automatic Cleanup**: Expired bans and old tracking data are automatically purged
- **Real-time Monitoring**: Events and statistics for all security actions
- **Memory Efficient**: Designed to handle high-traffic scenarios without memory leaks

#### Protection Against:

- **Connection Flooding**: Limits rapid connection attempts from single IPs
- **Malformed Messages**: Detects and bans clients sending invalid stratum messages
- **Socket Flooding**: Protects against buffer overflow attacks
- **Share Spam**: Works with existing share-based banning system
- **Repeated Offenders**: Progressive bans become longer with each strike

#### How the Ban System Works:

1. **First Offense**: 10-minute ban (1x duration)
2. **Second Offense**: 20-minute ban (2x duration)
3. **Third Offense**: 24-hour "permanent" ban
4. **Automatic Expiration**: All bans expire automatically after their duration
5. **Cleanup**: Old tracking data is purged every 5 minutes to prevent memory bloat

#### Important Notes:

**WSL2 Users**:
If running your pool in WSL2, be aware that all connections appear to come from the same internal NAT IP (typically `172.x.x.x`). This means:

- Banning an attacker would ban ALL miners
- You should set `"enabled": false` for development
- For production, deploy on native Linux or use HAProxy with PROXY protocol

**TCP Proxy Protocol**:
If using HAProxy or nginx with PROXY protocol:

1. Set `"tcpProxyProtocol": true` in your pool config
2. Configure your load balancer to send PROXY headers
3. The pool will extract real client IPs from PROXY headers

**Production Deployment**:
For maximum security in production:

- Enable the security module with conservative thresholds
- Monitor security statistics regularly
- Use external DDoS protection (Cloudflare, AWS Shield, etc.)
- Deploy on native Linux for accurate IP tracking
- Consider multiple security layers (firewall + pool security)

#### Implementation Details:

The security module is implemented in `lib/security.js` and integrates with:

- **Connection Handler**: Checks for bans on new connections
- **Stratum Protocol**: Validates all incoming messages
- **Socket Layer**: Monitors buffer sizes and data rates
- **Pool Manager**: Coordinates bans across multiple coin pools

All security tracking is in-memory for performance, with automatic cleanup every 5 minutes to prevent memory growth.

---

<div align="center">

## Maintained By

### **janos-raul**

#### Developer & Maintainer

[![Website](https://img.shields.io/badge/Pool-sha256--mining.go.ro-blue?style=for-the-badge)](https://sha256-mining.go.ro:55000)

_Building high-performance SHA256 mining infrastructure_

</div>

---

## Credits

- Original stratum-pool developers
- [vekexasia](//github.com/vekexasia) - co-developer & great tester
- [LucasJones](//github.com/LucasJones) - got p2p block notify working
- [TheSeven](//github.com/TheSeven) - technical guidance
- SHA256-NOMP Contributors - AsicBoost, solo mining, and PROP implementation

## Donations

To support continued development:

- BTC: `bc1q0aa3k39ww33z24p3wpk72jjn32h2n5rfr85pnx`
- BTCS: `bs1q8dnz4q52czdusl8hy04fw3jryj2kc3earck3y2`
- BCH: `qzhpajyfz7yvl8963rre5zqdp72pqy47ysttst0wmr`

## License

Released under the GNU General Public License v2

http://www.gnu.org/licenses/gpl-2.0.html
