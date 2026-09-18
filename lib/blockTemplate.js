var merkleTree = require("./merkleTree.js");
var transactions = require("./transactions.js");
var util = require("./util.js");

/**
 * The BlockTemplate class holds a single mining job.
 * It encapsulates block template data from the daemon and provides methods
 * to serialize block data and validate share submissions.
 *
 * @class BlockTemplate
 * @param {string} jobId - Unique identifier for this job
 * @param {Object} rpcData - Block template data from getblocktemplate RPC
 * @param {Buffer} poolAddressScript - Pool's address script for coinbase output
 * @param {Buffer} extraNoncePlaceholder - Placeholder for extranonce in coinbase
 * @param {boolean} txMessages - Whether to embed the pool OP_RETURN signature
 * @param {Array} recipients - Fee recipients for coinbase outputs
 * @param {string} [txMessageText] - Custom OP_RETURN message text; falls back to the default if omitted
 * @param {string} [blockIdentifier] - Per-coin identifier embedded in the coinbase scriptSig; falls back to "nodeStratum" if omitted
 */
var BlockTemplate = (module.exports = function BlockTemplate(
  jobId,
  rpcData,
  poolAddressScript,
  extraNoncePlaceholder,
  txMessages,
  recipients,
  txMessageText,
  blockIdentifier
) {
  //private members
  var submits = [];

  function getMerkleHashes(steps) {
    return steps.map(function (step) {
      return step.toString("hex");
    });
  }

  function getTransactionBuffers(txs) {
    var txHashes = txs.map(function (tx) {
      var hash = tx.txid || tx.hash;
      if (!hash) {
        throw new Error(
          "Transaction missing both txid and hash: " + JSON.stringify(tx)
        );
      }
      return util.uint256BufferFromHash(hash);
    });
    return [null].concat(txHashes);
  }

  //public members
  this.rpcData = rpcData;
  this.jobId = jobId;

  // CLEAN: Use native BigInt consistently
  this.target = rpcData.target
    ? BigInt("0x" + rpcData.target)
    : util.bignumFromBitsHex(rpcData.bits); // Already returns BigInt

  // CLEAN: Use native BigInt for difficulty calculation
  var diff1BigInt = BigInt(
    "0x00000000ffff0000000000000000000000000000000000000000000000000000"
  );
  var precisionFactor = BigInt(1e9);
  var difficultyBigInt = (diff1BigInt * precisionFactor) / this.target;
  this.difficulty = Number(difficultyBigInt) / 1e9;

  this.prevHashReversed = util
    .reverseByteOrder(Buffer.from(rpcData.previousblockhash, "hex"))
    .toString("hex");
  this.transactionData = Buffer.concat(
    rpcData.transactions.map(function (tx) {
      return Buffer.from(tx.data, "hex");
    })
  );
  this.merkleTree = new merkleTree(getTransactionBuffers(rpcData.transactions));
  this.merkleBranch = getMerkleHashes(this.merkleTree.steps);
  this.generationTransaction = transactions.CreateGeneration(
    rpcData,
    poolAddressScript,
    extraNoncePlaceholder,
    txMessages,
    recipients,
    txMessageText,
    blockIdentifier
  );

  /**
   * Serializes the coinbase transaction with the provided extranonces.
   */
  this.serializeCoinbase = function (extraNonce1, extraNonce2) {
    return Buffer.concat([
      this.generationTransaction[0],
      extraNonce1,
      extraNonce2,
      this.generationTransaction[1],
    ]);
  };

  /**
   * Serializes a block header according to Bitcoin protocol specification.
   */
  this.serializeHeader = function (merkleRoot, nTime, nonce, version) {
    var header = Buffer.alloc(80);
    var position = 0;
    header.write(nonce, position, 4, "hex");
    header.write(rpcData.bits, (position += 4), 4, "hex");
    header.write(nTime, (position += 4), 4, "hex");
    header.write(merkleRoot, (position += 4), 32, "hex");
    header.write(rpcData.previousblockhash, (position += 32), 32, "hex");

    // Use provided version for ASICBoost support, or default to rpcData version
    var actualVersion = version || rpcData.version;
    header.writeUInt32BE(actualVersion, position + 32);

    return util.reverseBuffer(header);
  };

  /**
   * Serializes a complete block including header and all transactions.
   */
  this.serializeBlock = function (header, coinbase) {
    return Buffer.concat([
      header,
      util.varIntBuffer(this.rpcData.transactions.length + 1),
      coinbase,
      this.transactionData,
    ]);
  };

  this.registerSubmit = function (
    extraNonce1,
    extraNonce2,
    nTime,
    nonce,
    version
  ) {
    var submission = extraNonce1 + extraNonce2 + nTime + nonce;
    if (version) {
      submission += version; // Include version for AsicBoost duplicate detection
    }

    if (submits.indexOf(submission) === -1) {
      submits.push(submission);
      return true;
    }
    return false;
  };

  /**
   * Gets the job parameters for Stratum mining.notify message.
   * Enhanced to provide AsicBoost-compatible version field.
   */
  this.getJobParams = function () {
    if (!this.jobParams) {
      // Ensure version is AsicBoost-compatible
      var jobVersion = this.rpcData.version;
      var versionHex = util.packInt32BE(jobVersion).toString("hex");

      this.jobParams = [
        this.jobId,
        this.prevHashReversed,
        this.generationTransaction[0].toString("hex"),
        this.generationTransaction[1].toString("hex"),
        this.merkleBranch,
        versionHex, // This version will be modified by AsicBoost miners
        this.rpcData.bits,
        util.packUInt32BE(this.rpcData.curtime).toString("hex"),
        true,
      ];
    }
    return this.jobParams;
  };
});