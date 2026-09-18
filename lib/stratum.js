/**
 * @module stratum
 * @description Implements the Stratum mining protocol for cryptocurrency pools.
 * Handles client connections, message validation, and mining operations.
 */

var net = require("net");
var events = require("events");

var util = require("./util.js");

// Constants for input validation
var MAX_STRING_LENGTH = 1024;
var MAX_ARRAY_LENGTH = 100;
var ALLOWED_METHODS = [
  "mining.subscribe",
  "mining.authorize",
  "mining.submit",
  "mining.get_transactions",
  "mining.configure",
  "mining.extranonce.subscribe",
  "mining.set_version_mask",
  "mining.multi_version",
  "client.reconnect",
  "ping",
  "mining.suggest_difficulty",
];

/**
 * Generates unique subscription IDs for Stratum clients.
 * The ID consists of a fixed prefix followed by a counter.
 *
 * @class SubscriptionCounter
 * @private
 */
var SubscriptionCounter = function () {
  var count = 0;
  var padding = "deadbeefcafebabe";
  return {
    next: function () {
      count++;
      if (Number.MAX_VALUE === count) count = 0;
      return padding + util.packInt64LE(count).toString("hex");
    },
  };
};

/**
 * Represents a connected Stratum mining client.
 * Handles all communication with individual miners.
 *
 * @class StratumClient
 * @extends {EventEmitter}
 * @param {Object} options - Client configuration
 * @param {net.Socket} options.socket - Network socket for the client
 * @param {Object} options.banning - Ban configuration settings
 * @param {string} options.subscriptionId - Unique subscription ID
 * @param {Object} options.authorizeFn - Function to authorize workers
 *
 * @fires StratumClient#subscription - When client subscribes
 * @fires StratumClient#submit - When client submits a share
 * @fires StratumClient#malformedMessage - On invalid message format
 * @fires StratumClient#socketError - On socket errors
 * @fires StratumClient#socketTimeout - On socket timeout
 * @fires StratumClient#socketDisconnect - When socket disconnects
 * @fires StratumClient#triggerBan - When client should be banned
 */
var StratumClient = function (options) {
  var pendingDifficulty = null;

  //private members
  this.socket = options.socket;
  this.remoteAddress = options.socket.remoteAddress;
  var banning = options.banning;
  var _this = this;
  this.lastActivity = Date.now();

  this.initialDifficulty = -1;
  this.minimumDifficulty = -1;
  this.isSoloMining = false;
  this.shares = { valid: 0, invalid: 0 };

  this.asicboost = false; // Client supports AsicBoost
  this.versionMask = null; // Negotiated version rolling mask
  this.versionRolling = false; // Version rolling enabled
  this.negotiatedExtensions = {}; // Store all negotiated capabilities
  this.multiVersion = false; // Multi-version (overt AsicBoost) enabled
  this.multiVersionCount = 0; // Number of versions requested
  this.currentVersions = []; // Current version array for this client
  this.supportsExtranonceSubscribe = false; // Extranonce subscription support
  this.extraNonce2Size = null; // Size of extraNonce2 for this client
  this.preAuthAsicBoost = null; // Store AsicBoost config before auth
  this.connectionSequence = []; // Track connection flow for debugging
  this.isWhatsminer = false; // Whatsminer/S21/similar miner detection flag
  this.requiresExtendedTimeout = false; // Flag for miners needing extended timeouts

  // Log new connection
  _this.emit(
    "log",
    "debug",
    "Stratum New Connection from " + _this.remoteAddress
  );

  setupSocket();

  var considerBan =
    !banning || !banning.enabled
      ? function () {
          return false;
        }
      : function (shareValid) {
          if (shareValid === true) _this.shares.valid++;
          else _this.shares.invalid++;
          var totalShares = _this.shares.valid + _this.shares.invalid;
          if (totalShares >= banning.checkThreshold) {
            var percentBad = (_this.shares.invalid / totalShares) * 100;
            if (percentBad < banning.invalidPercent)
              _this.shares = { valid: 0, invalid: 0 };
            else {
              _this.emit(
                "triggerBan",
                _this.shares.invalid +
                  " out of the last " +
                  totalShares +
                  " shares were invalid"
              );
              _this.socket.destroy();
              return true;
            }
          }
          return false;
        };

  /**
   * Validates a stratum message
   * @param {Object} message Stratum message
   * @returns {Object} Validation result
   * @property {Boolean} valid True if the message is valid
   * @property {String|undefined} error Error message if the message is invalid
   */
  function validateMessage(message) {
    // Basic structure validation
    if (!message || typeof message !== "object") {
      return { valid: false, error: "Invalid message format" };
    }

    // Validate method
    if (!message.method || typeof message.method !== "string") {
      return { valid: false, error: "Missing or invalid method" };
    }

    if (!ALLOWED_METHODS.includes(message.method)) {
      return { valid: false, error: "Unknown method: " + message.method };
    }

    // Validate id
    if (message.id !== null && message.id !== undefined) {
      if (typeof message.id !== "string" && typeof message.id !== "number") {
        return { valid: false, error: "Invalid message id type" };
      }
      if (
        typeof message.id === "string" &&
        message.id.length > MAX_STRING_LENGTH
      ) {
        return { valid: false, error: "Message id too long" };
      }
    }

    // Validate params
    if (message.params !== undefined) {
      if (!Array.isArray(message.params)) {
        return { valid: false, error: "Params must be an array" };
      }
      if (message.params.length > MAX_ARRAY_LENGTH) {
        return { valid: false, error: "Too many parameters" };
      }

      // Validate each parameter
      for (var i = 0; i < message.params.length; i++) {
        var param = message.params[i];

        // Check string parameters
        if (typeof param === "string") {
          if (param.length > MAX_STRING_LENGTH) {
            return { valid: false, error: "Parameter " + i + " too long" };
          }
          // Check for null bytes or control characters
          if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(param)) {
            return {
              valid: false,
              error: "Invalid characters in parameter " + i,
            };
          }
        }

        // Check arrays
        if (Array.isArray(param) && param.length > MAX_ARRAY_LENGTH) {
          return { valid: false, error: "Parameter " + i + " array too long" };
        }
      }
    }
    if (message.method === "mining.configure" && message.params) {
      // mining.configure should have exactly 2 parameters: [extensions_array, extension_params_object]
      if (message.params.length !== 2) {
        return {
          valid: false,
          error: "mining.configure requires exactly 2 parameters",
        };
      }

      // First parameter should be array of requested extensions
      if (!Array.isArray(message.params[0])) {
        return {
          valid: false,
          error: "mining.configure first parameter must be array of extensions",
        };
      }

      // Second parameter should be object with extension parameters
      if (message.params[1] && typeof message.params[1] !== "object") {
        return {
          valid: false,
          error: "mining.configure second parameter must be object",
        };
      }
    }

    return { valid: true };
  }

  /**
   * Handles an incoming Stratum message. Emits a 'unknownStratumMethod'
   * event if the method is not implemented.
   *
   * @param {Object} message - Stratum message object
   * @private
   */
  function handleMessage(message) {
    // S21 debugging: log all stratum messages
    // Debug: Uncomment for verbose method call logging
    // console.log(
    //   "[STRATUM-DEBUG] Method:",
    //   message.method,
    //   "from:",
    //   _this.workerName || _this.remoteAddress
    // );
    // _this.emit(
    //   "log",
    //   "debug",
    //   "Stratum RX: " +
    //     message.method +
    //     " from " +
    //     (_this.workerName || _this.remoteAddress)
    // );
    //console.log('[WhatsMiner Debug] Method:', message.method, 'on connection:', _this.remoteAddress, 'SubscriptionID:', options.subscriptionId);

    switch (message.method) {
      case "mining.subscribe":
        //console.log('[Debug] Calling handleSubscribe');
        handleSubscribe(message);
        break;
      case "mining.authorize":
        // console.log('[Debug] Calling handleAuthorize');
        handleAuthorize(message, true /*reply to socket*/);
        break;
      case "mining.submit":
        _this.lastActivity = Date.now();
        // console.log('mining.submit message from miner');
        handleSubmit(message);
        break;
      case "mining.get_transactions":
        sendJson({
          id: null,
          result: [],
          error: true,
        });
        break;
      case "ping":
        //  console.log('ping message from miner');
        _this.lastActivity = Date.now();
        sendJson({
          id: null,
          result: [],
          method: "pong",
        });
        break;
      case "mining.configure":
        //  console.log('mining.configure message from miner');
        handleConfigure(message);
        break;
      case "mining.extranonce.subscribe":
        //  console.log('mining.extranonce.subscribe message from miner');
        handleExtraNonceSubscribe(message);
        break;
      case "mining.set_version_mask":
        //  console.log('mining.set_version_mask message from miner');
        handleSetVersionMask(message);
        break;
      case "mining.multi_version":
        // Handle multi_version (overt AsicBoost) request
        var requestedVersionCount =
          message.params && message.params[0] ? parseInt(message.params[0]) : 0;

        // Check if coin supports multi_version
        var multiVersionConfig = options.coin.multiVersion;
        var isEnabled = multiVersionConfig && multiVersionConfig.enabled;
        var maxVersions =
          (multiVersionConfig && multiVersionConfig.maxVersions) || 4;

        if (!isEnabled) {
          sendJson({
            id: message.id,
            result: null,
            error: [20, "Multi-version not enabled for this coin", null],
          });
          _this.emit(
            "log",
            "debug",
            "Miner " +
              _this.remoteAddress +
              " requested mining.multi_version but it's disabled"
          );
          break;
        }

        // Validate requested count
        if (requestedVersionCount < 1 || requestedVersionCount > maxVersions) {
          sendJson({
            id: message.id,
            result: null,
            error: [
              20,
              "Invalid version count (must be 1-" + maxVersions + ")",
              null,
            ],
          });
          _this.emit(
            "log",
            "warning",
            "Miner " +
              _this.remoteAddress +
              " requested invalid version count: " +
              requestedVersionCount
          );
          break;
        }

        // Enable multi_version for this client
        _this.multiVersion = true;
        _this.multiVersionCount = requestedVersionCount;
        _this.asicboost = true; // Multi-version is a form of AsicBoost

        // Return success (actual versions will be sent in mining.notify)
        sendJson({
          id: message.id,
          result: true,
          error: null,
        });

        _this.emit(
          "log",
          "info",
          "Miner " +
            _this.remoteAddress +
            " enabled multi_version with " +
            requestedVersionCount +
            " version(s)"
        );
        break;
      case "mining.suggest_difficulty":
        var suggestedDiff = message.params[0];
        var effectiveDiff =
          _this.initialDifficulty > 0 ? _this.initialDifficulty : _this.difficulty;

        _this.emit(
          "log",
          "info",
          "Miner " +
            _this.remoteAddress +
            " suggested diff " +
            suggestedDiff +
            " but pool is using fixed difficulty: " +
            effectiveDiff +
            (_this.initialDifficulty > 0 ? " (from password d= override)" : "")
        );

        // Set the pool's chosen difficulty regardless of suggestion
        _this.difficulty = effectiveDiff;

        sendJson({
          id: null,
          method: "mining.set_difficulty",
          params: [effectiveDiff],
        });

        sendJson({
          id: message.id,
          result: true,
          error: null,
        });
        break;
      case "client.reconnect":
        handleReconnect(message);
        break;
      default:
        _this.emit("unknownStratumMethod", message);
        break;
    }
  }

  function handleSetVersionMask(message) {
    if (!_this.asicboost) {
      sendJson({
        id: message.id,
        result: false,
        error: [20, "AsicBoost not enabled", null],
      });
      return;
    }

    // Miner is requesting to use version rolling
    // Respond with the version mask the pool accepts
    var requestedMask = message.params && message.params[0];

    // Get pool's configured version mask (same logic as mining.configure)
    var poolVersionMask = options.coin.versionMask
      ? parseInt(options.coin.versionMask, 16)
      : 0x3fffe000;

    _this.emit(
      "log",
      "debug",
      "Miner " +
        _this.remoteAddress +
        " requested version mask: " +
        requestedMask +
        ", pool using: " +
        poolVersionMask
    );

    // Send the pool's version mask to the miner
    sendJson({
      id: message.id,
      result: true,
      error: null,
    });

    // Also send the version mask via mining.set_version_mask notification
    sendJson({
      id: null,
      method: "mining.set_version_mask",
      params: ["0x" + poolVersionMask.toString(16)],
    });
  }

  /**
   * Handle MiningRigRentals client.reconnect requests
   * MRR uses this to redirect miners to allocated ports
   */
  function handleReconnect(message) {
    _this.emit(
      "log",
      "debug",
      "MRR reconnect request from " + _this.getLabel()
    );

    var params = message.params || [];

    if (params.length === 0) {
      // Empty params = reconnect to same host/port immediately
      sendJson({
        id: message.id,
        result: true,
        error: null,
      });
    } else if (params.length >= 2) {
      var newHost = params[0];
      var newPort = params[1];
      var waitTime = params[2] || 0;

      // Debug: Uncomment for MiningRigRentals redirect troubleshooting
      // _this.emit("log", "debug", "MRR redirect to " + newHost + ":" + newPort);

      // Acknowledge redirect
      sendJson({
        id: message.id,
        result: true,
        error: null,
      });

      // Emit event for pool manager
      _this.emit("reconnectRequested", {
        host: newHost,
        port: newPort,
        waitTime: waitTime,
        client: _this,
      });
    } else {
      sendJson({
        id: message.id,
        result: false,
        error: [20, "invalid reconnect parameters", null],
      });
    }
  }
  function handleExtraNonceSubscribe(message) {
    _this.supportsExtranonceSubscribe = true;
    sendJson({
      id: message.id,
      result: true,
      error: null,
    });

    // IMPORTANT: After subscribing, immediately send the current extranonce values
    // This is required by miners like S21 Hydro PowerPlay-BMS
    if (_this.extraNonce1) {
      console.log(
        "[STRATUM-DEBUG] Sending mining.set_extranonce after subscription:",
        _this.extraNonce1,
        "size:",
        _this.extraNonce2Size
      );
      sendJson({
        id: null,
        method: "mining.set_extranonce",
        params: [_this.extraNonce1, _this.extraNonce2Size],
      });
    }
  }

  /**
   * Handles a mining.subscribe stratum message
   * @param {Object} message - Stratum message object
   * @fires StratumClient#subscription
   * @private
   */
  function handleSubscribe(message) {
    //console.log('[Debug] Received mining.subscribe from:', _this.remoteAddress);
    _this.connectionSequence.push("subscribe");

    if (!_this.authorized) {
      _this.requestedSubscriptionBeforeAuth = true;
    }
    // NEW: Capture user agent from subscription params
    if (message.params && message.params[0]) {
      _this.userAgent = message.params[0];
      _this.emit("subscriptionReceived", message.params[0]);
      // Debug: Uncomment to log user agent capture (verbose on every connection)
      // _this.emit("log", "debug", "Captured user agent: " + message.params[0]);

      if (_this.preAuthAsicBoost) {
        _this.asicboost = _this.preAuthAsicBoost.enabled;
        _this.versionMask = _this.preAuthAsicBoost.versionMask;
        _this.negotiatedExtensions = _this.preAuthAsicBoost.extensions;
        // Debug: Uncomment for AsicBoost troubleshooting
        // _this.emit("log", "debug", "Restored AsicBoost config from pre-auth");
      }
    }
    _this.emit(
      "subscription",
      { userAgent: _this.userAgent }, // Pass user agent to subscription handler
      function (error, extraNonce1, extraNonce2Size) {
        if (error) {
          sendJson({
            id: message.id,
            result: null,
            error: error,
          });
          return;
        }

        _this.extraNonce1 = extraNonce1;
        _this.extraNonce2Size = extraNonce2Size;

        // Log subscription details
        _this.emit(
          "log",
          "debug",
          "Subscription for " +
            (_this.workerName || _this.remoteAddress) +
            " - extraNonce1: " +
            extraNonce1 +
            " (" + (extraNonce1.length / 2) + " bytes)" +
            ", extraNonce2Size: " +
            extraNonce2Size
        );

        // Standard subscription response - same for all clients
        sendJson({
          id: message.id,
          result: [
            [
              ["mining.set_difficulty", options.subscriptionId],
              ["mining.notify", options.subscriptionId],
            ],
            extraNonce1,
            extraNonce2Size,
          ],
          error: null,
        });

        // console.log('[Debug] Sent subscription response to:', _this.remoteAddress);
        // console.log('[Stratum] Client subscribed: ' + _this.remoteAddress +
        //            ', extraNonce1: ' + extraNonce1);
      }
    );
  }

  function handleAuthorize(message, replyToSocket) {
    _this.connectionSequence.push("authorize");
    _this.workerName = message.params[0];
    _this.workerPass = message.params[1];

    // Detect miners that configure before authorize (Whatsminer, S21, etc.)
    var sequence = _this.connectionSequence.join(",");
    if (
      sequence === "configure,subscribe,authorize" ||
      sequence === "configure,authorize"
    ) {
      _this.emit(
        "log",
        "info",
        "Whatsminer/S21-style sequence detected for " +
          _this.workerName +
          " (sequence: " +
          sequence +
          ")"
      );

      // IMPORTANT: Ensure ASICBoost state is preserved
      if (_this.preAuthAsicBoost && !_this.asicboost) {
        _this.asicboost = _this.preAuthAsicBoost.enabled;
        _this.versionMask = _this.preAuthAsicBoost.versionMask;
        _this.negotiatedExtensions = _this.preAuthAsicBoost.extensions;
        _this.emit(
          "log",
          "info",
          "Restored ASICBoost state after auth for " + _this.workerName
        );
      }
    }

    options.authorizeFn(
      _this.remoteAddress,
      options.socket.localPort,
      _this.workerName,
      _this.workerPass,
      function (result) {
        _this.authorized = !result.error && result.authorized;

        if (replyToSocket) {
          sendJson({
            id: message.id,
            result: _this.authorized,
            error: result.error,
          });
        }

        // If the authorizer wants us to close the socket lets do it.
        if (result.disconnect === true) {
          console.log(
            "[STRATUM-DEBUG] DESTROYING socket - AUTHORIZER disconnect:",
            _this.remoteAddress
          );
          options.socket.destroy();
        } else {
          // Step 1: Clean parameter parsing
          parseWorkerParameters(_this.workerPass);

          if (_this.requestedSubscriptionBeforeAuth) {
            if (_this.initialDifficulty > 0) {
              _this.sendDifficulty(_this.initialDifficulty);
            }
          } else {
            // S21 Hydro and similar miners that authorize without subscribing first
            // Automatically create subscription for them
            _this.emit(
              "log",
              "debug",
              "Miner authorized without subscription - auto-subscribing: " +
                _this.workerName
            );

            // Trigger subscription event to assign extraNonce
            _this.emit(
              "subscription",
              [],
              function (error, extraNonce1, extraNonce2Size) {
                if (!error) {
                  // Store subscription details
                  _this.extraNonce1 = extraNonce1;
                  _this.emit(
                    "log",
                    "debug",
                    "Auto-subscription successful for " +
                      _this.workerName +
                      " - extraNonce1: " +
                      extraNonce1
                  );
                }
              }
            );

            // Now send difficulty and job
            _this.emit("needDifficulty");
          }

          // Emit event for successful authorization
          if (_this.authorized) {
            _this.emit("minerAuthorized", _this.workerName);
            _this.emit(
              "log",
              "info",
              "Miner authorized: " +
                _this.workerName +
                ", UserAgent: " +
                (_this.userAgent || "unknown")
            );
          }
        }
      }
    );
  }

  function parseWorkerParameters(passwordString) {
    if (!passwordString || passwordString === "x") return;

    var passwordArgs = passwordString.split(",");
    _this.emit(
      "log",
      "debug",
      "Parsing auth parameters: " + passwordArgs.join(",")
    );

    for (var i = 0; i < passwordArgs.length; i++) {
      var param = passwordArgs[i].trim();
      if (param.indexOf("=") === -1) continue;

      var key = param.substr(0, param.indexOf("=")).toLowerCase();
      var value = param.substr(param.indexOf("=") + 1);

      switch (key) {
        case "d":
          _this.initialDifficulty = parseInt(value) || -1;
          _this.emit(
            "log",
            "debug",
            "Set initial difficulty: " + _this.initialDifficulty
          );
          break;

        case "md":
          // Set a per-client difficulty floor. The port's existing shared
          // varDiff instance (attached at connection time) reads this
          // directly and respects it as an effective minimum, clamped to
          // the port's own configured minDiff/maxDiff — no separate
          // varDiff instance is created here.
          _this.minimumDifficulty = parseInt(value) || -1;
          _this.emit(
            "log",
            "debug",
            "Set minimum difficulty: " + _this.minimumDifficulty
          );
          break;

        case "tt":
          // Requested varDiff targetTime (seconds between shares). Only
          // takes effect if the port's varDiff.minerConfigurable.targetTime
          // is set; the value is clamped to that range in varDiff.js.
          _this.customTargetTime = parseFloat(value) || -1;
          _this.emit(
            "log",
            "debug",
            "Requested varDiff target time: " + _this.customTargetTime
          );
          break;

        case "rt":
          // Requested varDiff retargetTime (seconds between adjustments).
          // Only takes effect if the port's
          // varDiff.minerConfigurable.retargetTime is set; clamped in
          // varDiff.js.
          _this.customRetargetTime = parseFloat(value) || -1;
          _this.emit(
            "log",
            "debug",
            "Requested varDiff retarget time: " + _this.customRetargetTime
          );
          break;

        case "vp":
          // Requested varDiff variancePercent. Only takes effect if the
          // port's varDiff.minerConfigurable.variancePercent is set;
          // clamped in varDiff.js.
          _this.customVariancePercent = parseFloat(value) || -1;
          _this.emit(
            "log",
            "debug",
            "Requested varDiff variance percent: " +
              _this.customVariancePercent
          );
          break;

        case "m":
          _this.isSoloMining = value.trim().toLowerCase() === "solo"; // Keep existing property name
          _this.emit(
            "log",
            "info",
            "Solo mining mode: " +
              _this.isSoloMining +
              " for " +
              _this.workerName
          );
          break;

        default:
          _this.emit(
            "log",
            "warning",
            "Unknown auth parameter: " + key + "=" + value
          );
          break;
      }
    }
  }
  /**
   * Handles mining.configure messages for ASICBoost compatibility.
   * Compatible with AvalonMiner, NiceHash, and other mining services.
   *
   * @param {Object} message - Stratum message with parameters
   * @returns {undefined}
   */
  function handleConfigure(message) {
    _this.connectionSequence.push("configure");
    _this.emit(
      "log",
      "debug",
      "mining.configure called for client: " + _this.getLabel()
    );

    if (!_this.authorized) {
      _this.emit(
        "log",
        "info",
        "Whatsminer/S21-style flow detected - configure before authorize from " +
          _this.remoteAddress
      );
      _this.isWhatsminer = true; // Generic flag for miners with this behavior
      _this.requiresExtendedTimeout = true;

      // Extend socket timeout for Whatsminer/S21 and similar miners
      if (options.socket && options.socket.setTimeout) {
        options.socket.setTimeout(30000); // 30 seconds
        _this.emit(
          "log",
          "debug",
          "Extended socket timeout for Whatsminer/S21-style miner"
        );
      }
    }

    // Check if this miner already has AsicBoost configured from a previous connection
    var minerKey = _this.remoteAddress + ":" + (_this.workerName || "unknown");
    if (_this.asicboost) {
      //	console.log('[MinerState] Miner', minerKey, 'already has AsicBoost enabled, reusing configuration');
      sendJson({
        id: message.id,
        result: _this.negotiatedExtensions || {},
        error: null,
      });
      return;
    }

    var supported = {};

    // Basic parameter validation
    if (
      !message.params ||
      !Array.isArray(message.params) ||
      message.params.length < 1
    ) {
      sendJson({
        id: message.id,
        result: null,
        error: [20, "invalid params", null],
      });
      return;
    }

    var extensions = message.params[0];
    var extensionParams = message.params[1] || {};

    // Extensions should be an array
    if (!Array.isArray(extensions)) {
      sendJson({
        id: message.id,
        result: {},
        error: [20, "invalid params", null],
      });
      return;
    }

    // Handle version-rolling extension with proper ASICBoost compatibility
    if (extensions.includes("version-rolling")) {
      // Use a permissive mask that works with most miners
      //var poolVersionMask = 0x1fffe000;  // Standard ASICBoost mask
      var poolVersionMask = options.coin.versionMask
        ? parseInt(options.coin.versionMask, 16)
        : 0x3fffe000; // Standard ASICBoost mask matching CKPool
      var clientRequestedMask = extensionParams["version-rolling.mask"];
      var clientMinBitCount =
        extensionParams["version-rolling.min-bit-count"] ||
        options.coin.versionRollingMinBits ||
        16;

      // Calculate negotiated mask
      var negotiatedMask = poolVersionMask;
      if (clientRequestedMask) {
        var clientMask = parseInt(clientRequestedMask, 16);
        if (!isNaN(clientMask)) {
          // Use intersection of pool and client masks
          negotiatedMask = poolVersionMask & clientMask;
        }
      }

      // Count bits in negotiated mask
      var bitCount = 0;
      var temp = negotiatedMask;
      while (temp > 0) {
        bitCount += temp & 1;
        temp >>>= 1;
      }

      // Only enable if we have enough bits
      if (bitCount >= clientMinBitCount) {
        supported["version-rolling"] = true;
        supported["version-rolling.mask"] = negotiatedMask.toString(16); // NO "0x" prefix for Bitmain firmware compatibility
        supported["version-rolling.min-bit-count"] = bitCount;

        _this.asicboost = true;
        _this.versionMask = negotiatedMask;
        _this.versionRolling = true;
        _this.negotiatedExtensions = supported; // Store all capabilities

        if (!_this.authorized) {
          _this.preAuthAsicBoost = {
            enabled: true,
            versionMask: negotiatedMask,
            extensions: supported,
          };
          _this.emit(
            "log",
            "info",
            "Stored pre-auth AsicBoost config for Whatsminer"
          );
        }

        // console.log('[Stratum] Client ' + (_this.workerName || 'unknown') +
        //            ' enabled version-rolling with mask: 0x' + negotiatedMask.toString(16));
        _this.emit("asicboostEnabled", {
          versionMask: negotiatedMask,
          bitCount: bitCount,
        });
      } else {
        _this.emit("asicboostDisabled");
        supported["version-rolling"] = false;
        _this.emit(
          "log",
          "warning",
          "Client " +
            (_this.workerName || "unknown") +
            " version-rolling disabled - insufficient bits"
        );
      }
    }

    // After handleAuthorize completes for non-AsicBoost clients
    if (!_this.asicboost) {
      _this.emit("asicboostDisabled");
    }

    // Process other extensions
    if (extensions.includes("minimum-difficulty")) {
      var minDiff = extensionParams["minimum-difficulty.value"];
      if (minDiff && minDiff > 0) {
        supported["minimum-difficulty"] = true;
        supported["minimum-difficulty.value"] = minDiff;
        _this.minimumDifficulty = minDiff;
      }
    }

    if (extensions.includes("subscribe-extranonce")) {
      supported["subscribe-extranonce"] = true;
      _this.supportsExtranonceSubscribe = true;
    }

    sendJson({
      id: message.id,
      result: supported,
      error: null,
    });
  }

  /**
   * Handles mining.submit messages from clients.
   *
   * @param {Object} message - Stratum message with parameters
   *
   * @returns {undefined}
   */
  function handleSubmit(message) {
    //console.log('[Debug] Submit received from:', _this.remoteAddress, 'jobId:', message.params[1]);
    if (!_this.authorized) {
      sendJson({
        id: message.id,
        result: null,
        error: [24, "unauthorized worker", null],
      });
      considerBan(false);
      return;
    }
    if (!_this.extraNonce1) {
      sendJson({
        id: message.id,
        result: null,
        error: [25, "not subscribed", null],
      });
      considerBan(false);
      return;
    }

    // Validate submit parameters - now supporting both 5 and 6 parameter formats
    if (!message.params || message.params.length < 5) {
      sendJson({
        id: message.id,
        result: null,
        error: [20, "missing submit parameters", null],
      });
      considerBan(false);
      return;
    }

    // Extract parameters
    var workerName = message.params[0];
    var jobId = message.params[1];
    var extraNonce2 = message.params[2];
    var nTime = message.params[3];
    var nonce = message.params[4];
    var version = message.params[5]; // Optional 6th parameter for AsicBoost

    // Validate basic parameters (same as before)
    if (typeof workerName !== "string" || workerName.length > 128) {
      sendJson({
        id: message.id,
        result: null,
        error: [20, "invalid worker name", null],
      });
      considerBan(false);
      return;
    }

    if (typeof jobId !== "string" || !jobId.match(/^[0-9a-fA-F]+$/)) {
      sendJson({
        id: message.id,
        result: null,
        error: [20, "invalid job id", null],
      });
      considerBan(false);
      return;
    }

    if (
      typeof extraNonce2 !== "string" ||
      !extraNonce2.match(/^[0-9a-fA-F]+$/)
    ) {
      sendJson({
        id: message.id,
        result: null,
        error: [20, "invalid extranonce2", null],
      });
      considerBan(false);
      return;
    }

    if (typeof nTime !== "string" || !nTime.match(/^[0-9a-fA-F]{8}$/)) {
      sendJson({
        id: message.id,
        result: null,
        error: [20, "invalid ntime", null],
      });
      considerBan(false);
      return;
    }

    if (typeof nonce !== "string" || !nonce.match(/^[0-9a-fA-F]{8}$/)) {
      sendJson({
        id: message.id,
        result: null,
        error: [20, "invalid nonce", null],
      });
      considerBan(false);
      return;
    }

    // NEW: AsicBoost version parameter validation
    var isAsicBoostSubmit = false;
    var validatedVersion = null;

    if (version !== undefined) {
      // Version parameter provided - validate it
      if (typeof version !== "string" || !version.match(/^[0-9a-fA-F]{8}$/)) {
        sendJson({
          id: message.id,
          result: null,
          error: [20, "invalid version format", null],
        });
        considerBan(false);
        return;
      }

      // Convert hex string to number for validation
      var versionNum = parseInt(version, 16);

      // Check if this client is using multi_version (overt AsicBoost)
      if (
        _this.multiVersion &&
        _this.currentVersions &&
        _this.currentVersions.length > 0
      ) {
        // Validate that submitted version is in the allowed array
        var versionAllowed = false;
        for (var i = 0; i < _this.currentVersions.length; i++) {
          if (_this.currentVersions[i] === versionNum) {
            versionAllowed = true;
            break;
          }
        }

        if (!versionAllowed) {
          sendJson({
            id: message.id,
            result: null,
            error: [20, "version not in allowed array", null],
          });
          considerBan(false);
          _this.emit(
            "log",
            "warning",
            "Multi-version client " +
              workerName +
              " submitted invalid version: 0x" +
              version +
              " (allowed: " +
              _this.currentVersions
                .map(function (v) {
                  return "0x" + v.toString(16);
                })
                .join(", ") +
              ")"
          );
          return;
        }

        // Valid multi-version submit
        isAsicBoostSubmit = true;
        validatedVersion = version;
        _this.emit(
          "log",
          "debug",
          "Multi-version submit from " +
            workerName +
            " with version: 0x" +
            version
        );
      }
      // Check if this client negotiated version-rolling (covert AsicBoost)
      else if (_this.asicboost && _this.versionMask) {
        // Validate that version bits are within allowed mask
        var maskedVersion = versionNum & _this.versionMask;

        // Check if any bits outside the mask are modified from the original job version
        // This would need the original job version to compare against
        // For now, we'll accept any version that only uses bits within the mask

        if (maskedVersion !== 0) {
          // AsicBoost submit detected
          isAsicBoostSubmit = true;
          validatedVersion = version;
          // console.log('[Stratum] AsicBoost submit detected from ' + workerName +
          //            ' - version: 0x' + version + ', mask: 0x' + _this.versionMask.toString(16));
        }
      } else {
        // Client provided version but hasn't negotiated AsicBoost
        //console.log('[Stratum] Version parameter provided by non-AsicBoost client: ' + workerName);
        // We can still accept it, just pass it through
        validatedVersion = version;
      }
    } //else {
    // No version parameter - traditional submit
    // if (_this.asicboost) {
    //      console.log('[Stratum] Traditional submit from AsicBoost-capable client: ' + workerName);
    //  }
    //}

    // Prepare submit data object
    var submitData = {
      name: workerName,
      jobId: jobId,
      extraNonce2: extraNonce2,
      nTime: nTime,
      nonce: nonce,
      // NEW: Include version and AsicBoost status
      version: validatedVersion,
      isAsicBoost: isAsicBoostSubmit,
      versionMask: _this.versionMask,
      // Include client info for debugging/logging
      clientAddress: _this.remoteAddress,
      workerAgent: _this.workerAgent || "unknown",
      // Include client's specific extraNonce2Size for validation
      extraNonce2Size: _this.extraNonce2Size,
    };

    // Emit submit event with enhanced data
    _this.emit("submit", submitData, function (error, result) {
      if (!considerBan(result)) {
        sendJson({
          id: message.id,
          result: result,
          error: error,
        });
      }
    });
  }

  /**
   * Helper function to send JSON data to the stratum client.
   * Can be given any number of arguments, which are JSON.stringified
   * and written to the socket with a newline appended to each argument.
   * @param {...Object} data - Data to send to the client.
   * @return {undefined}
   */
  function sendJson(json) {
    var message = JSON.stringify(json) + "\n";
    // Debug: Uncomment for verbose stratum protocol TX logging
    // console.log(
    //   "[STRATUM-DEBUG] TX to",
    //   (_this.workerName || _this.remoteAddress) + ":",
    //   JSON.stringify(json)
    // );
    // _this.emit(
    //   "log",
    //   "debug",
    //   "Stratum TX: " +
    //     (json.method || "response") +
    //     " to " +
    //     (_this.workerName || _this.remoteAddress) +
    //     " - " +
    //     JSON.stringify(json).substring(0, 200)
    // );

    // Add error handling for disconnected clients
    try {
      if (_this.socket && !_this.socket.destroyed) {
        _this.socket.write(message);
      }
    } catch (err) {
      // Client disconnected - emit disconnect event to clean up
      if (err.code === "EPIPE" || err.code === "ECONNRESET") {
        _this.emit("socketDisconnect");
      } else {
        _this.emit("socketError", err);
      }
    }
  }

  /**
   * Set up the socket and associated event listeners.
   *
   * @emits socketDisconnect
   * @emits socketError
   * @emits socketFlooded
   * @emits tcpProxyError
   * @emits malformedMessage
   * @emits checkBan
   */
  function setupSocket() {
    var socket = options.socket;
    var dataBuffer = "";
    socket.setEncoding("utf8");

    if (options.tcpProxyProtocol === true) {
      socket.once("data", function (d) {
        if (d.indexOf("PROXY") === 0) {
          _this.remoteAddress = d.split(" ")[2];
        } else {
          _this.emit("tcpProxyError", d);
        }
        _this.emit("checkBan");
      });
    } else {
      _this.emit("checkBan");
    }
    socket.on("data", function (d) {
      // Debug: Uncomment for verbose stratum protocol RX logging
      // console.log(
      //   "[STRATUM-DEBUG] Raw data from",
      //   _this.remoteAddress,
      //   ":",
      //   d.toString().trim()
      // );
      // _this.emit(
      //   "log",
      //   "debug",
      //   "Stratum Raw RX from " +
      //     _this.remoteAddress +
      //     ": " +
      //     d.toString().trim().substring(0, 200)
      // );
      //console.log('[Debug] Raw data received from', _this.remoteAddress, ':', d.toString().trim());

      dataBuffer += d;
      if (Buffer.byteLength(dataBuffer, "utf8") > 10240) {
        //10KB
        dataBuffer = "";
        console.log(
          "[STRATUM-DEBUG] DESTROYING socket - FLOODED:",
          _this.remoteAddress
        );
        _this.emit("socketFlooded");
        socket.destroy();
        return;
      }
      if (dataBuffer.indexOf("\n") !== -1) {
        var messages = dataBuffer.split("\n");
        var incomplete = dataBuffer.slice(-1) === "\n" ? "" : messages.pop();
        messages.forEach(function (message) {
          if (message === "") return;
          //console.log('[Debug] Processing message:', message);
          var messageJson;
          try {
            messageJson = JSON.parse(message);
            // Debug: Uncomment for JSON message parsing details
            // console.log(
            //   "[STRATUM-DEBUG] Parsed:",
            //   messageJson.method || "no-method",
            //   "id:",
            //   messageJson.id
            // );
            //console.log('[Debug] Parsed JSON:', messageJson);
          } catch (e) {
            console.log("[STRATUM-DEBUG] JSON parse ERROR:", e.message);
            //console.log('[Debug] JSON parse error:', e.message, 'Message:', message);
            if (options.tcpProxyProtocol !== true || d.indexOf("PROXY") !== 0) {
              console.log(
                "[STRATUM-DEBUG] DESTROYING socket - MALFORMED:",
                _this.remoteAddress,
                "Message:",
                message.substring(0, 50)
              );
              _this.emit("malformedMessage", message);
              socket.destroy();
            }
            return;
          }

          if (messageJson) {
            var validation = validateMessage(messageJson);
            if (!validation.valid) {
              console.log(
                "[STRATUM-DEBUG] Validation FAILED:",
                validation.error,
                "Method:",
                messageJson.method
              );
              //console.log('[Debug] Message validation failed:', validation.error);
              _this.emit(
                "malformedMessage",
                message + " - " + validation.error
              );
              sendJson({
                id: messageJson.id || null,
                result: null,
                error: [20, validation.error, null],
              });
              considerBan(false);
              return;
            }
            //console.log('[Debug] Message validated, calling handleMessage');
            handleMessage(messageJson);
          }
        });
        dataBuffer = incomplete;
      }
    });
    socket.on("close", function () {
      console.log(
        "[STRATUM-DEBUG] Socket CLOSED for",
        _this.workerName || _this.remoteAddress,
        "- Buffer:",
        dataBuffer.substring(0, 100)
      );
      _this.emit(
        "log",
        "debug",
        "Stratum Socket CLOSED for " +
          (_this.workerName || _this.remoteAddress) +
          (_this.userAgent ? " (User Agent: " + _this.userAgent + ")" : "")
      );
      _this.emit("socketDisconnect");
    });
    socket.on("error", function (err) {
      console.log(
        "[STRATUM-DEBUG] Socket ERROR for",
        _this.workerName || _this.remoteAddress,
        "- Error:",
        err.code,
        err.message
      );
      _this.emit(
        "log",
        "debug",
        "Stratum Socket ERROR for " +
          (_this.workerName || _this.remoteAddress) +
          ": " +
          err.code +
          " " +
          err.message
      );
      if (err.code !== "ECONNRESET") _this.emit("socketError", err);
    });
  }

  /**
   * Return a string identifying this connection, of the form:
   * <workerName> [<ipAddress>]
   * If the worker is unauthorized, <workerName> will be "(unauthorized)"
   * @return {string}
   */
  this.getLabel = function () {
    return (
      (_this.workerName || "(unauthorized)") + " [" + _this.remoteAddress + "]"
    );
  };

  /**
   * Queues a new difficulty for the next time the client requests a difficulty.
   * This is useful for when the upstream pool changes its difficulty.
   * @param {number} requestedNewDifficulty - The new difficulty to send to the client
   * @return {boolean} - Always true
   */
  this.enqueueNextDifficulty = function (requestedNewDifficulty) {
    pendingDifficulty = requestedNewDifficulty;
    return true;
  };

  /**
   * IF the given difficulty is valid and new it'll send it to the client.
   * returns boolean
   **/
  this.sendDifficulty = function (difficulty) {
    if (difficulty === this.difficulty) return false;

    _this.previousDifficulty = _this.difficulty;
    _this.difficulty = difficulty;
    sendJson({
      id: null,
      method: "mining.set_difficulty",
      params: [difficulty], //[512],
    });
    return true;
  };

  /**
   * Send extranonce change notification to the client if they subscribed.
   * This notifies the client when extraNonce1 or extraNonce2Size changes.
   * Typically used when reconnecting or when pool reassigns extranonce space.
   * @param {string} extraNonce1 - The new extraNonce1 value
   * @param {number} extraNonce2Size - The new extraNonce2 size
   * @return {boolean} - true if notification was sent, false if not subscribed
   */
  this.sendExtraNonce = function (extraNonce1, extraNonce2Size) {
    if (!_this.supportsExtranonceSubscribe) {
      return false;
    }

    sendJson({
      id: null,
      method: "mining.set_extranonce",
      params: [extraNonce1, extraNonce2Size],
    });

    _this.emit(
      "log",
      "debug",
      "Sent extranonce change to " +
        (_this.workerName || _this.remoteAddress) +
        " - extraNonce1: " +
        extraNonce1 +
        ", extraNonce2Size: " +
        extraNonce2Size
    );

    return true;
  };

  /**
   * Send a new mining job to the client.
   *
   * If the client hasn't submitted a share in a while, this will disconnect the client.
   * If there's a pending difficulty, it'll send that first.
   * @param {array} jobParams - The parameters for the mining.notify method, typically [jobId, prevHash, coinb1, coinb2, merkleBranch, version, bits, target, timestamp, cleanJobs]
   * @return {undefined}
   */
  this.sendMiningJob = function (jobParams) {
    if (_this.isWhatsminer && options.debug) {
      _this.emit(
        "log",
        "debug",
        "Sending job to Whatsminer/S21-style miner " +
          (_this.workerName || "unauthorized")
      );
    }
    var lastActivityAgo = Date.now() - _this.lastActivity;
    if (lastActivityAgo > options.connectionTimeout * 1000) {
      _this.emit(
        "socketTimeout",
        "last submitted a share was " +
          ((lastActivityAgo / 1000) | 0) +
          " seconds ago"
      );
      _this.socket.destroy();
      return;
    }

    if (pendingDifficulty !== null) {
      var result = _this.sendDifficulty(pendingDifficulty);
      pendingDifficulty = null;
      if (result) {
        _this.emit("difficultyChanged", _this.difficulty);
      }
    }

    // NEW: Modify job parameters for AsicBoost and multi_version clients
    var finalJobParams = jobParams;

    // Handle multi_version clients (overt AsicBoost)
    if (
      _this.multiVersion &&
      _this.multiVersionCount > 0 &&
      jobParams.length >= 7
    ) {
      // Clone the job parameters to avoid modifying the original
      finalJobParams = jobParams.slice();

      // Generate version array for this client
      var originalVersion = parseInt(finalJobParams[5], 16);
      var versionArray = [];

      // Generate sequential versions
      for (var i = 0; i < _this.multiVersionCount; i++) {
        var versionHex = (originalVersion + i).toString(16);
        // Pad to 8 characters
        while (versionHex.length < 8) versionHex = "0" + versionHex;
        versionArray.push(versionHex);
      }

      // Store versions for share validation
      _this.currentVersions = versionArray.map(function (v) {
        return parseInt(v, 16);
      });

      // Replace single version with array at index 5
      finalJobParams[5] = versionArray;

      _this.emit(
        "log",
        "debug",
        "Sending multi_version job to " +
          (_this.workerName || "unknown") +
          " with versions: [" +
          versionArray.join(", ") +
          "]"
      );
    }
    // Handle version-rolling clients (covert AsicBoost)
    else if (_this.asicboost && _this.versionMask && jobParams.length >= 7) {
      // Clone the job parameters to avoid modifying the original
      finalJobParams = jobParams.slice();

      // The version is typically at index 5 in mining.notify parameters
      // Standard format: [jobId, prevHash, coinb1, coinb2, merkleBranch, version, bits, ntime, cleanJobs]
      var originalVersion = parseInt(finalJobParams[5], 16);

      // For AsicBoost clients, we need to ensure the version allows for rolling
      // The pool should have already prepared a suitable base version
      // We don't modify it here, but we could log it for debugging

      //console.log('[Stratum] Sending AsicBoost job to ' + (_this.workerName || 'unknown') +
      //           ' - base version: 0x' + finalJobParams[5] +
      //           ', mask: 0x' + _this.versionMask.toString(16));
    }

    sendJson({
      id: null,
      method: "mining.notify",
      params: finalJobParams,
    });
  };

  /**
   * Updates the version mask for this client (BIP 310).
   * Sends a mining.set_version_mask notification to the client.
   * @param {number} newMask - The new version mask to use
   * @return {boolean} - True if client supports version rolling
   */
  this.setVersionMask = function (newMask) {
    if (!_this.asicboost) {
      return false;
    }

    _this.versionMask = newMask;
    sendJson({
      id: null,
      method: "mining.set_version_mask",
      params: [newMask.toString(16)],
    });
    return true;
  };

  /**
   * Manually authorizes the client with the given username and password.
   * This is useful in tests where you want to connect a client to the pool
   * programatically.
   * @param {string} username - The username to authorize with
   * @param {string} password - The password to authorize with
   */
  this.manuallyAuthClient = function (username, password) {
    handleAuthorize(
      { id: 1, params: [username, password] },
      false /*do not reply to miner*/
    );
  };

  /**
   * Copy the extraNonce1, previousDifficulty and difficulty from another StratumClient instance.
   * If extraNonce changes and client subscribed to extranonce notifications, sends mining.set_extranonce.
   * @param {StratumClient} otherClient - The other StratumClient instance to copy from.
   */
  this.manuallySetValues = function (otherClient) {
    var oldExtraNonce1 = _this.extraNonce1;

    _this.extraNonce1 = otherClient.extraNonce1;
    _this.extraNonce2Size = otherClient.extraNonce2Size;
    _this.previousDifficulty = otherClient.previousDifficulty;
    _this.difficulty = otherClient.difficulty;

    // Notify client if extranonce changed and they subscribed
    if (oldExtraNonce1 !== _this.extraNonce1 && _this.extraNonce2Size) {
      _this.sendExtraNonce(_this.extraNonce1, _this.extraNonce2Size);
    }
  };
};

StratumClient.prototype.__proto__ = events.EventEmitter.prototype;
/**
 * The Stratum protocol server implementation.
 * Manages multiple ports, client connections, and mining job broadcasts.
 *
 * @class StratumServer
 * @extends {EventEmitter}
 * @param {Object} options - Server configuration
 * @param {Object} options.ports - Port configurations (port number -> config)
 * @param {number} options.connectionTimeout - Client connection timeout (ms)
 * @param {number} options.jobRebroadcastTimeout - Job rebroadcast timeout (seconds)
 * @param {Object} [options.banning] - IP banning configuration
 * @param {boolean} options.banning.enabled - Whether banning is enabled
 * @param {number} options.banning.time - Ban duration in seconds
 * @param {number} options.banning.purgeInterval - Interval to purge old bans
 * @param {boolean} [options.tcpProxyProtocol] - Whether to use HAProxy PROXY protocol
 * @param {Function} authorizeFn - Function to authorize workers
 *
 * @fires StratumServer#client.connected - When a new miner connects
 * @fires StratumServer#client.disconnected - When a miner disconnects
 * @fires StratumServer#started - When the server is up and running
 * @fires StratumServer#broadcastTimeout - When job broadcast timeout occurs
 * @fires StratumServer#bootedBannedWorker - When a banned worker is kicked
 */
var StratumServer = (exports.Server = function StratumServer(
  options,
  authorizeFn
) {
  //private members
  var _this = this;

  // Add miner state tracking at the top of StratumServer constructor
  var minerStates = {}; // Track miner state by worker+userAgent combination

  // Helper functions for miner state management
  function getMinerKey(workerName, userAgent) {
    // Use worker name + user agent to uniquely identify miners
    return (workerName || "unknown") + "::" + (userAgent || "unknown");
  }

  function saveMinerState(workerName, userAgent, client) {
    var key = getMinerKey(workerName, userAgent);
    minerStates[key] = {
      asicboost: client.asicboost,
      versionMask: client.versionMask,
      versionRolling: client.versionRolling,
      negotiatedExtensions: client.negotiatedExtensions,
      difficulty: client.difficulty,
      lastActivity: Date.now(),
      workerName: workerName,
      userAgent: userAgent,
    };
    //console.log('[MinerState] Saved state for miner:', key);
  }

  function restoreMinerState(workerName, userAgent, client) {
    var key = getMinerKey(workerName, userAgent);
    var savedState = minerStates[key];

    if (savedState && Date.now() - savedState.lastActivity < 300000) {
      // 5 minutes
      client.asicboost = savedState.asicboost;
      client.versionMask = savedState.versionMask;
      client.versionRolling = savedState.versionRolling;
      client.negotiatedExtensions = savedState.negotiatedExtensions;
      client.difficulty = savedState.difficulty;

      //console.log('[MinerState] Restored state for miner:', key,
      //           'AsicBoost:', client.asicboost,
      //          'Mask:', client.versionMask ? '0x' + client.versionMask.toString(16) : 'none');
      return true;
    }
    return false;
  }

  // Debug log the version mask configuration
  var poolVersionMask;
  if (options.coin.versionMask) {
    poolVersionMask = parseInt(options.coin.versionMask, 16);
    _this.emit(
      "log",
      "info",
      "Server configured with versionMask: 0x" + poolVersionMask.toString(16)
    );
  } else {
    poolVersionMask = 0x3fffe000;
    _this.emit(
      "log",
      "info",
      "No versionMask in options, using default 0x" +
        poolVersionMask.toString(16)
    );
  }

  var bannedMS = options.banning ? options.banning.time * 1000 : null;
  var stratumClients = {};
  var subscriptionCounter = SubscriptionCounter();
  var rebroadcastTimeout;
  var bannedIPs = {};

  // AsicBoost statistics
  var asicboostStats = {
    totalClients: 0,
    asicboostClients: 0,
    traditionalClients: 0,
  };

  /**
   * Check if the client is banned and act accordingly.
   * If banned, it will be disconnected and receive a 'kickedBannedIP' event.
   * If the ban has expired, the client will receive a 'forgaveBannedIP' event.
   * @param {StratumClient} client - The stratum client to check.
   */
  /**
   * Check if the client is banned and act accordingly.
   */
  function checkBan(client) {
    // Security: honor bans issued by SecurityManager (malformed/flood/strikes)
    if (options.securityManager) {
      var secBan = options.securityManager.isBanned(client.remoteAddress);
      if (secBan) {
        client.socket.destroy();
        client.emit(
          "kickedBannedIP",
          secBan.permanent ? Infinity : secBan.remainingTime
        );
        return;
      }
    }

    if (
      options.banning &&
      options.banning.enabled &&
      client.remoteAddress in bannedIPs
    ) {
      var bannedTime = bannedIPs[client.remoteAddress];
      var bannedTimeAgo = Date.now() - bannedTime;
      var timeLeft = bannedMS - bannedTimeAgo;
      if (timeLeft > 0) {
        client.socket.destroy();
        client.emit("kickedBannedIP", (timeLeft / 1000) | 0);
      } else {
        delete bannedIPs[client.remoteAddress];
        client.emit("forgaveBannedIP");
      }
    }
  }

  this.getLabel = function () {
    return (_this.workerName || "unknown") + " [" + _this.remoteAddress + "]";
  };

  /**
   * Handle a new incoming client connection.
   * This method is called for every new client and returns the subscriptionId for the client.
   * @param {net.Socket} socket - The new client socket.
   * @returns {String} The subscriptionId for the client.
   */
  /**
   * Handle a new incoming client connection.
   */
  this.handleNewClient = function (socket) {
    // Security: reject immediately if this IP is already banned
    if (options.securityManager) {
      if (options.securityManager.isBanned(socket.remoteAddress)) {
        socket.destroy();
        return null;
      }

      // Security: enforce max-connections-per-IP rate limit
      var connectionAllowed = options.securityManager.recordConnection(
        socket.remoteAddress
      );
      if (!connectionAllowed) {
        socket.destroy();
        return null;
      }
    }

    socket.setKeepAlive(true);
    var subscriptionId = subscriptionCounter.next();
    var client = new StratumClient({
      subscriptionId: subscriptionId,
      authorizeFn: authorizeFn,
      socket: socket,
      banning: options.banning,
      connectionTimeout: options.connectionTimeout,
      tcpProxyProtocol: options.tcpProxyProtocol,
      coin: options.coin,
    });

    stratumClients[subscriptionId] = client;
    asicboostStats.totalClients++;

    // Enhanced connection logging
    //console.log('[WhatsMiner Debug] New connection, SubscriptionID:', subscriptionId);

    // Listen for user agent capture
    client.on("subscriptionReceived", function (userAgent) {
      client.userAgent = userAgent;
      //console.log('[MinerState] User agent captured:', userAgent);

      // Try to restore state if we have both worker name and user agent
      if (client.workerName && userAgent) {
        restoreMinerState(client.workerName, userAgent, client);
      }
    });

    // Listen for AsicBoost capability detection
    client.on("asicboostEnabled", function (capabilities) {
      asicboostStats.asicboostClients++;
      //console.log('[Stratum] AsicBoost enabled for client ' + client.remoteAddress +
      //           ' with mask: 0x' + capabilities.versionMask.toString(16));
      _this.emit("client.asicboostEnabled", client, capabilities);
    });

    client.on("asicboostDisabled", function () {
      asicboostStats.traditionalClients++;
      //console.log('[Stratum] Traditional mining for client ' + client.remoteAddress);
    });

    client.on("log", function (severity, message) {
      _this.emit("log", severity, message); // Just pass it up to the server level
    });

    // Listen for miner authorization
    client.on("minerAuthorized", function (workerName) {
      _this.emit(
        "log",
        "info",
        "Miner authorized: " +
          workerName +
          ", UserAgent: " +
          (client.userAgent || "unknown")
      );

      // Try to restore state now that we have worker name
      if (client.userAgent) {
        restoreMinerState(workerName, client.userAgent, client);
      }

      // Save current state when miner gets authorized
      if (client.userAgent) {
        saveMinerState(workerName, client.userAgent, client);
      }
    });

    _this.emit("client.connected", client);

    client
      .on("socketDisconnect", function () {
        // Update statistics when client disconnects
        asicboostStats.totalClients--;
        if (client.asicboost) {
          asicboostStats.asicboostClients--;
        } else {
          asicboostStats.traditionalClients--;
        }

        // Save state before disconnect for potential reconnection
        if (client.workerName && client.userAgent) {
          saveMinerState(client.workerName, client.userAgent, client);
        }

        _this.removeStratumClientBySubId(subscriptionId);
        _this.emit("client.disconnected", client);
      })
      .on("checkBan", function () {
        checkBan(client);
      })
      .on("triggerBan", function () {
        _this.addBannedIP(client.remoteAddress);
      });

    return subscriptionId;
  };

  /**
   * Broadcasts a new mining job to all connected clients.
   * Enhanced to handle both AsicBoost and traditional clients appropriately.
   * @param {Object} jobParams - The parameters of the new mining job.
   * @fires StratumServer#broadcastTimeout
   * @see {@link StratumClient#sendMiningJob}
   */
  this.broadcastMiningJobs = function (jobParams) {
    var asicboostCount = 0;
    var traditionalCount = 0;

    for (var clientId in stratumClients) {
      var client = stratumClients[clientId];

      // Send job to client (client will handle AsicBoost-specific modifications)
      client.sendMiningJob(jobParams);

      // Count client types for logging
      if (client.asicboost) {
        asicboostCount++;
      } else {
        traditionalCount++;
      }
    }

    // Enhanced logging
    if (asicboostCount > 0 || traditionalCount > 0) {
      _this.emit(
        "log",
        "debug",
        "Broadcast job to " +
          asicboostCount +
          " AsicBoost clients, " +
          traditionalCount +
          " traditional clients"
      );
    }

    /* Some miners will consider the pool dead if it doesn't receive a job for around a minute.
           So every time we broadcast jobs, set a timeout to rebroadcast in X seconds unless cleared. */
    clearTimeout(rebroadcastTimeout);
    rebroadcastTimeout = setTimeout(function () {
      _this.emit("broadcastTimeout");
    }, (options.jobRebroadcastTimeout || 55) * 1000);
  };

  /**
   * Get AsicBoost statistics for monitoring
   * @returns {Object} Statistics about AsicBoost usage
   */
  this.getAsicBoostStats = function () {
    return {
      totalClients: asicboostStats.totalClients,
      asicboostClients: asicboostStats.asicboostClients,
      traditionalClients: asicboostStats.traditionalClients,
      asicboostPercentage:
        asicboostStats.totalClients > 0
          ? Math.round(
              (asicboostStats.asicboostClients / asicboostStats.totalClients) *
                100
            )
          : 0,
      poolVersionMask: "0x" + poolVersionMask.toString(16),
    };
  };

  /**
   * Get detailed client information including AsicBoost capabilities
   * @returns {Array} Array of client information objects
   */
  this.getClientDetails = function () {
    var clients = [];
    for (var clientId in stratumClients) {
      var client = stratumClients[clientId];
      clients.push({
        subscriptionId: clientId,
        remoteAddress: client.remoteAddress,
        workerName: client.workerName || "unknown",
        asicboost: client.asicboost,
        versionMask: client.versionMask
          ? "0x" + client.versionMask.toString(16)
          : null,
        difficulty: client.difficulty,
        lastActivity: client.lastActivity,
        shares: client.shares,
      });
    }
    return clients;
  };

  (function init() {
    //Interval to look through bannedIPs for old bans and remove them in order to prevent a memory leak
    if (options.banning && options.banning.enabled) {
      setInterval(function () {
        for (ip in bannedIPs) {
          var banTime = bannedIPs[ip];
          if (Date.now() - banTime > options.banning.time) delete bannedIPs[ip];
        }
      }, 1000 * options.banning.purgeInterval);
    }

    // Periodic AsicBoost statistics logging
    setInterval(function () {
      var stats = _this.getAsicBoostStats();
      if (stats.totalClients > 0) {
        _this.emit(
          "log",
          "info",
          "AsicBoost Stats - Total: " +
            stats.totalClients +
            ", AsicBoost: " +
            stats.asicboostClients +
            " (" +
            stats.asicboostPercentage +
            "%), Traditional: " +
            stats.traditionalClients
        );
      }
    }, 300000); // Log every 5 minutes

    var serversStarted = 0;
    Object.keys(options.ports).forEach(function (port) {
      net
        .createServer({ allowHalfOpen: false }, function (socket) {
          _this.handleNewClient(socket);
        })
        .listen(parseInt(port), function () {
          serversStarted++;
          if (serversStarted == Object.keys(options.ports).length) {
            _this.emit(
              "log",
              "special",
              "All servers started with AsicBoost support enabled"
            );
            _this.emit("started");
          }
        });
    });
  })();

  //public members

  /**
   * Bans a given IP address.
   * @param {String} ipAddress - The IP address of the client to ban.
   * @fires StratumServer#bootedBannedWorker
   */
  this.addBannedIP = function (ipAddress) {
    bannedIPs[ipAddress] = Date.now();
  };

  /**
   * Removes an IP from stratum's own local ban store (share-based banning).
   * Used to keep stratum.js in sync when SecurityManager unbans or expires
   * an IP that also has an entry here.
   * @param {String} ipAddress - The IP address to unban.
   */
  this.removeBannedIP = function (ipAddress) {
    delete bannedIPs[ipAddress];
  };

  /**
   * Returns an object with all currently connected clients, where the keys are the subscriptionIds
   * and the values are StratumClient instances.
   * @return {Object} The object with all currently connected clients.
   */
  this.getStratumClients = function () {
    return stratumClients;
  };

  /**
   * Removes a client from the list of connected clients by its subscriptionId.
   * @param {String} subscriptionId - The subscriptionId of the client to remove.
   */
  this.removeStratumClientBySubId = function (subscriptionId) {
    delete stratumClients[subscriptionId];
  };

  /**
   * Manually adds a stratum client to the pool's list of connected clients. Useful for testing.
   * @param {Object} clientObj - An object containing the following properties:
   *                              - `socket`: The socket object of the client.
   *                              - `workerName`: The worker name of the client.
   *                              - `workerPass`: The worker password of the client.
   */
  this.manuallyAddStratumClient = function (clientObj) {
    var subId = _this.handleNewClient(clientObj.socket);
    if (subId != null) {
      // not banned!
      stratumClients[subId].manuallyAuthClient(
        clientObj.workerName,
        clientObj.workerPass
      );
      stratumClients[subId].manuallySetValues(clientObj);
    }
  };
});
StratumServer.prototype.__proto__ = events.EventEmitter.prototype;