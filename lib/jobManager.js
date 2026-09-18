var events = require("events");
var crypto = require("crypto");

var algos = require("./algoProperties.js");
var util = require("./util.js");
var blockTemplate = require("./blockTemplate.js");
var transactions = require("./transactions.js");

var diff1 = BigInt(
  "0x00000000ffff0000000000000000000000000000000000000000000000000000"
);

function formatCompactNumber(value) {
  var n = Number(value);
  if (!isFinite(n)) return String(value);

  var sign = n < 0 ? "-" : "";
  n = Math.abs(n);

  var units = ["", "K", "M", "G", "T", "P", "E"];
  var unitIndex = 0;
  while (n >= 1000 && unitIndex < units.length - 1) {
    n /= 1000;
    unitIndex++;
  }

  return sign + n.toFixed(2) + units[unitIndex];
}

/**
 * Generates unique extranonce values for each subscriber.
 * Uses instance ID to ensure uniqueness across pool instances.
 *
 * @class ExtraNonceCounter
 * @param {number} [configInstanceId] - Optional instance ID for multi-instance deployments
 */
var ExtraNonceCounter = function (configInstanceId) {
  var instanceId = configInstanceId || crypto.randomBytes(4).readUInt32LE(0);
  var counter = instanceId << 27;

  /**
   * Gets the next extranonce value.
   *
   * @method next
   * @returns {string} Hex-encoded extranonce value
   */
  this.next = function () {
    var extraNonce = util.packUInt32BE(Math.abs(counter++));
    return extraNonce.toString("hex");
  };

  this.size = 4; //bytes
};

/**
 * Generates unique job IDs for each new block template.
 * Wraps around at 0xffff to prevent overflow.
 *
 * @class JobCounter
 */
var JobCounter = function () {
  var counter = 0;

  /**
   * Gets the next job ID.
   *
   * @method next
   * @returns {string} Hex-encoded job ID
   */
  this.next = function () {
    counter++;
    if (counter % 0xffff === 0) counter = 1;
    return this.cur();
  };

  /**
   * Gets the current job ID without incrementing.
   *
   * @method cur
   * @returns {string} Current hex-encoded job ID
   */
  this.cur = function () {
    return counter.toString(16);
  };
};

/**
 * Manages mining jobs and validates submitted shares.
 * This class is responsible for creating new jobs from block templates,
 * tracking valid jobs, and processing share submissions.
 *
 * @class JobManager
 * @extends {EventEmitter}
 * @param {Object} options - Configuration options
 * @param {Object} options.coin - Coin-specific configuration
 * @param {string} options.coin.algorithm - Mining algorithm
 * @param {string} options.coin.reward - Reward type ('POW' or 'POS')
 * @param {boolean} [options.coin.asicboost] - Whether ASICBoost is enabled
 * @param {Buffer} options.poolAddressScript - Pool's address script for coinbase
 * @param {number} [options.instanceId] - Instance ID for extranonce generation
 *
 * @fires JobManager#newBlock - When a new block (previously unknown to the JobManager) is added
 * @fires JobManager#updatedBlock - When the current job is updated
 * @fires JobManager#share - When a worker submits a share
 * @fires JobManager#log - For logging events
 */
var JobManager = (module.exports = function JobManager(options) {
  //private members

  var _this = this;
  var jobCounter = new JobCounter();

  var shareMultiplier = algos[options.coin.algorithm].multiplier;

  //public members

  this.extraNonceCounter = new ExtraNonceCounter(options.instanceId);
  // Use 10-byte placeholder to support both standard and large extraNonce2 miners
  // Standard miners: 4 EN1 + 4 EN2 = 8 bytes (2 bytes padding unused)
  // S21/Whatsminer: 4 EN1 + 6 EN2 = 10 bytes (full placeholder used)
  this.extraNoncePlaceholder = Buffer.from("f000000ff111111fff22", "hex"); // 10 bytes
  // Default to 4-byte extraNonce2 for standard miners
  // S21/Whatsminer get 6 bytes via user-agent detection in pool.js
  this.extraNonce2Size = 4; // Standard 4-byte default

  this.currentJob;
  this.validJobs = {};

  var hashDigest = algos[options.coin.algorithm].hash(options.coin);

  // SHA256-only pool: coinbase and block hashing are always sha256d
  var coinbaseHasher = util.sha256d;

  var blockHasher = function () {
    return util.reverseBuffer(hashDigest.apply(this, arguments));
  };

  /**
   * Updates the current job with new RPC data without clearing valid jobs.
   * Used when updating an existing job with new transactions.
   *
   * @method updateCurrentJob
   * @param {Object} rpcData - Block template data from daemon RPC
   * @returns {boolean} Always returns true to indicate success
   * @fires JobManager#updatedBlock
   */
  this.updateCurrentJob = function (rpcData) {
    var tmpBlockTemplate = new blockTemplate(
      jobCounter.next(),
      rpcData,
      options.poolAddressScript,
      _this.extraNoncePlaceholder,
      options.coin.txMessages,
      options.recipients,
      options.coin.txMessageText,
      options.blockIdentifier
    );

    _this.currentJob = tmpBlockTemplate;

    _this.emit("updatedBlock", tmpBlockTemplate, true);

    _this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;

    return true;
  };

  /**
   * Processes a new block template from the daemon.
   * Determines if this is actually a new block and creates a new job if so.
   *
   * @method processTemplate
   * @param {Object} rpcData - Block template data from daemon RPC
   * @returns {boolean} True if a new block was processed, false otherwise
   * @fires JobManager#newBlock
   */
  this.processTemplate = function (rpcData) {
    // Debug logging for rpcData being processed
    //  _this.emit('log', 'debug', 'DEBUG: processTemplate called with rpcData');
    //  _this.emit('log', 'debug', 'DEBUG: rpcData.version = ' + rpcData.version);
    //  _this.emit('log', 'debug', 'DEBUG: rpcData.version (hex) = 0x' + rpcData.version.toString(16));
    //  _this.emit('log', 'debug', 'DEBUG: rpcData.previousblockhash = ' + rpcData.previousblockhash);
    //  _this.emit('log', 'debug', 'DEBUG: rpcData.height = ' + rpcData.height);

    /* Block is new if A) its the first block we have seen so far or B) the blockhash is different and the
           block height is greater than the one we have */
    var isNewBlock = typeof _this.currentJob === "undefined";
    if (
      !isNewBlock &&
      _this.currentJob.rpcData.previousblockhash !== rpcData.previousblockhash
    ) {
      isNewBlock = true;

      //If new block is outdated/out-of-sync than return
      if (rpcData.height < _this.currentJob.rpcData.height) return false;
    }

    if (!isNewBlock) return false;

    var tmpBlockTemplate = new blockTemplate(
      jobCounter.next(),
      rpcData,
      options.poolAddressScript,
      _this.extraNoncePlaceholder,
      options.coin.txMessages,
      options.recipients,
      options.coin.txMessageText,
      options.blockIdentifier
    );

    // Debug logging after blockTemplate creation
    // _this.emit('log', 'debug', 'DEBUG: blockTemplate created, rpcData.version stored = ' + tmpBlockTemplate.rpcData.version);

    this.currentJob = tmpBlockTemplate;

    this.validJobs = {};
    _this.emit("newBlock", tmpBlockTemplate);

    this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;

    return true;
  };

  /**
   * Processes a share submission from a miner.
   * Validates the share and checks if it meets block or share difficulty requirements.
   *
   * @method processShare
   * @param {string} jobId - Job ID the share is for
   * @param {number} previousDifficulty - Previous difficulty (for vardiff)
   * @param {number} difficulty - Current worker difficulty
   * @param {string} extraNonce1 - Worker's assigned extranonce1
   * @param {string} extraNonce2 - Miner-generated extranonce2
   * @param {string} nTime - Block timestamp (hex)
   * @param {string} nonce - Miner's nonce (hex)
   * @param {string} ipAddress - Worker's IP address
   * @param {number} port - Port the worker connected to
   * @param {string} workerName - Worker identifier (username.workername)
   * @returns {Object} Result object with error or success
   * @returns {Array} [result.error] - Error array [code, message] if share is invalid
   * @returns {boolean} [result.result] - True if share is valid
   * @returns {string} [result.blockHash] - Block hash if block was found
   * @fires JobManager#share
   */
  this.processShare = function (
    jobId,
    previousDifficulty,
    difficulty,
    extraNonce1,
    extraNonce2,
    nTime,
    nonce,
    ipAddress,
    port,
    workerName,
    versionMask,
    isSoloMining,
    version,
    isAsicBoost,
    clientContext
  ) {
    var shareError = function (error) {
      _this.emit("share", {
        job: jobId,
        ip: ipAddress,
        worker: workerName,
        difficulty: difficulty,
        isSoloMining: isSoloMining,
        error: error[1],
        isAsicBoost: isAsicBoost || false,
        version: version,
      });
      return { error: error, result: null };
    };

    var submitTime = (Date.now() / 1000) | 0;

    // Use client-specific extraNonce2Size if available, otherwise use default
    var expectedExtraNonce2Size = (clientContext && clientContext.extraNonce2Size)
      ? clientContext.extraNonce2Size
      : _this.extraNonce2Size;

    if (extraNonce2.length / 2 !== expectedExtraNonce2Size) {
      _this.emit(
        "log",
        "warning",
        "ExtraNonce2 size mismatch for " +
          workerName +
          " - Expected: " +
          expectedExtraNonce2Size +
          " bytes (" +
          expectedExtraNonce2Size * 2 +
          " hex chars)" +
          ", Received: " +
          extraNonce2.length / 2 +
          " bytes (" +
          extraNonce2.length +
          " hex chars)" +
          ", Value: " +
          extraNonce2
      );
      return shareError([20, "incorrect size of extranonce2"]);
    }

    var job = this.validJobs[jobId];
    if (typeof job === "undefined" || job.jobId != jobId) {
      return shareError([21, "job not found"]);
    }
    if (nTime.length !== 8) {
      return shareError([20, "incorrect size of ntime"]);
    }
    var nTimeInt = parseInt(nTime, 16);
    if (nTimeInt < job.rpcData.curtime || nTimeInt > submitTime + 7200) {
      return shareError([20, "ntime out of range"]);
    }
    if (nonce.length !== 8) {
      return shareError([20, "incorrect size of nonce"]);
    }

    // Enhanced duplicate detection for ASICBoost
    if (!job.registerSubmit(extraNonce1, extraNonce2, nTime, nonce, version)) {
      return shareError([22, "duplicate share"]);
    }

    var extraNonce1Buffer = Buffer.from(extraNonce1, "hex");
    var extraNonce2Buffer = Buffer.from(extraNonce2, "hex");

    var coinbaseBuffer = job.serializeCoinbase(
      extraNonce1Buffer,
      extraNonce2Buffer
    );
    var coinbaseHash = coinbaseHasher(coinbaseBuffer);

    var merkleRoot = util
      .reverseBuffer(job.merkleTree.withFirst(coinbaseHash))
      .toString("hex");

    // MINIMAL ASICBOOST ADDITION: Version handling
    var versionInt;
    var versionSource = "job-default";

    // Alternative: Validate and potentially correct the version mask
    if (version && isAsicBoost) {
      var submittedVersion = parseInt(version, 16);
      if (isNaN(submittedVersion)) {
        versionInt = job.rpcData.version;
        versionSource = "job-default-invalid-version";
      } else {
        var jobBaseVersion = job.rpcData.version;

        // Validate version mask - ensure it doesn't allow rolling critical bits
        var safeVersionMask = versionMask;

        // Critical bits that should NEVER be rollable:
        // Bit 31-30: Version bits (should be 00 for version 1, 01 for version 2, etc.)
        // Bit 29: BIP9 version bit
        var criticalBits = 0xe0000000; // Bits 29-31

        if ((versionMask & criticalBits) !== 0) {
          //   console.log('[Warning] Version mask 0x' + versionMask.toString(16) +
          //              ' allows rolling critical bits. Correcting...');
          safeVersionMask = versionMask & ~criticalBits;
          //   console.log('[Corrected] Safe version mask: 0x' + safeVersionMask.toString(16));
        }

        // Extract rollable bits from submitted version using safe mask
        var rolledBits = submittedVersion & safeVersionMask;

        // Create final version: base version with rollable bits cleared, then add rolled bits
        versionInt = (jobBaseVersion & ~safeVersionMask) | rolledBits;
        versionSource = "asicboost-rolled";

        //    console.log('[Debug] AsicBoost version calculation:');
        //    console.log('  Job base version: 0x' + jobBaseVersion.toString(16));
        //    console.log('  Submitted version: 0x' + submittedVersion.toString(16));
        //    console.log('  Original mask: 0x' + versionMask.toString(16));
        //    console.log('  Safe mask: 0x' + safeVersionMask.toString(16));
        //    console.log('  Rolled bits: 0x' + rolledBits.toString(16));
        //    console.log('  Final version: 0x' + versionInt.toString(16));
        //    console.log('  Base non-rollable: 0x' + (jobBaseVersion & (~safeVersionMask)).toString(16));
      }
    } else {
      // Traditional submit - use job's default version
      versionInt = job.rpcData.version;
      versionSource = "job-default";
    }

    var headerBuffer = job.serializeHeader(
      merkleRoot,
      nTime,
      nonce,
      versionInt
    );
    var headerHash = hashDigest(headerBuffer, nTimeInt);
    var headerBigNum = BigInt(
      "0x" + util.reverseBuffer(headerHash).toString("hex")
    );

    var blockHashInvalid;
    var blockHash;
    var blockHex;
    var algorithm = job.algorithm || options.coin.algorithm;
    var algoProps = algos[algorithm];

    if (!algoProps) {
      return shareError([
        24,
        `Algorithm properties not found for ${algorithm}`,
      ]);
    }

    var multiplier = algoProps.multiplier || 1;
    var shareDiff = (Number(diff1) / Number(headerBigNum)) * multiplier;
    var blockDiffAdjusted = job.difficulty * multiplier;

    var blockHexInvalid = job
      .serializeBlock(headerBuffer, coinbaseBuffer)
      .toString("hex");
    blockHashInvalid = blockHasher(headerBuffer, nTime).toString("hex");

    if (job.target >= headerBigNum) {
      blockHex = job
        .serializeBlock(headerBuffer, coinbaseBuffer)
        .toString("hex");
      blockHash = blockHasher(headerBuffer, nTime).toString("hex");

      // MINIMAL ASICBOOST ADDITION: Log ASICBoost block discovery
      if (isAsicBoost) {
        _this.emit(
          "log",
          "success",
          "ASICBoost block found! Worker: " +
            workerName +
            ", Version: 0x" +
            versionInt.toString(16)
        );
      }
    } else {
      if (options.emitInvalidBlockHashes)
        blockHashInvalid = util
          .reverseBuffer(util.sha256d(headerBuffer))
          .toString("hex");

      if (shareDiff / difficulty < 0.99) {
        if (previousDifficulty && shareDiff >= previousDifficulty) {
          difficulty = previousDifficulty;
        } else {
          return shareError([23, `low difficulty share of ${shareDiff}`]);
        }
      }
    }

    // Solo mining logic: emit share then return
    if (isSoloMining && !blockHex) {
      _this.emit(
        "log",
        "debug",
        "Solo share from " +
          workerName +
          " (diff: " +
          formatCompactNumber(shareDiff) +
          ") - no reward for non-block shares"
      );

      // EMIT THE SHARE BEFORE RETURNING
      _this.emit(
        "share",
        {
          job: jobId,
          ip: ipAddress,
          port: port,
          worker: workerName,
          height: job.rpcData.height,
          blockReward: job.rpcData.coinbasevalue,
          difficulty: difficulty,
          shareDiff: shareDiff.toFixed(8),
          blockDiff: blockDiffAdjusted,
          blockDiffActual: job.difficulty,
          blockHash: null, // No block found
          blockHashInvalid: blockHashInvalid,
          isAsicBoost: isAsicBoost || false,
          version: version,
          versionInt: versionInt,
          versionSource: versionSource,
          versionMask: versionMask,
          isSoloMining: true, // Mark as solo
          paymentMode: "solo",
        },
        null
      ); // No blockHex

      return { result: true, error: null, blockHash: null };
    }

    // Log solo block discovery
    if (isSoloMining && blockHex) {
      _this.emit(
        "log",
        "success",
        "SOLO BLOCK found by " +
          workerName +
          ", Difficulty: " +
          shareDiff.toFixed(8) +
          ", Block reward will go entirely to miner (minus pool fee)"
      );
      // Don't return here - let it continue to emit the share with blockHex
    }

    // Check if this is a regular pool share that didn't find a block
    if (!isSoloMining && !blockHex) {
      // Regular pool share - emit and continue
    }

    // This emission handles:
    // 1. Regular pool shares (both block and non-block)
    // 2. Solo blocks (when isSoloMining && blockHex)
    // The solo non-block shares were already handled above with early return
    _this.emit(
      "share",
      {
        job: jobId,
        ip: ipAddress,
        port: port,
        worker: workerName,
        height: job.rpcData.height,
        blockReward: job.rpcData.coinbasevalue,
        difficulty: difficulty,
        shareDiff: shareDiff.toFixed(8),
        blockDiff: blockDiffAdjusted,
        blockDiffActual: job.difficulty,
        blockHash: blockHash,
        blockHashInvalid: blockHashInvalid,
        isAsicBoost: isAsicBoost || false,
        version: version,
        versionInt: versionInt,
        versionSource: versionSource,
        versionMask: versionMask,
        clientContext: clientContext,
        isSoloMining: isSoloMining,
        paymentMode: isSoloMining
          ? "solo"
          : (clientContext && clientContext.paymentMode) || "default",
      },
      blockHex
    );

    return { result: true, error: null, blockHash: blockHash };
  };
});
JobManager.prototype.__proto__ = events.EventEmitter.prototype;