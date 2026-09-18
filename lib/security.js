/**
 * Stratum Security Module
 * Provides rate limiting and auto-banning functionality for pool connections
 *
 * @module security
 */

var events = require("events");

/**
 * Security manager for handling connection rate limiting and IP banning
 * @class SecurityManager
 * @extends {EventEmitter}
 */
function SecurityManager(options) {
  var _this = this;

  // Configuration with defaults
  this.options = {
    enabled: options.security?.enabled !== false, // Enabled by default

    // Rate limiting settings
    rateLimit: {
      enabled: options.security?.rateLimit?.enabled !== false,
      window: options.security?.rateLimit?.window || 60000, // 1 minute
      maxConnections: options.security?.rateLimit?.maxConnections || 10, // Max connections per IP per window
      maxMalformed: options.security?.rateLimit?.maxMalformed || 3, // Max malformed messages before ban
      maxFloods: options.security?.rateLimit?.maxFloods || 2, // Max flood detections before ban
    },

    // Ban settings
    ban: {
      enabled: options.security?.ban?.enabled !== false,
      duration: options.security?.ban?.duration || 600000, // 10 minutes default ban
      maxStrikes: options.security?.ban?.maxStrikes || 3, // Strikes before permanent ban
      permanentDuration: options.security?.ban?.permanentDuration || 86400000, // 24 hours
    },
  };

  // Tracking data structures
  this.connectionCounts = {}; // IP -> { count, firstConnection, window }
  this.malformedCounts = {}; // IP -> { count, firstMessage, window }
  this.floodCounts = {}; // IP -> { count, firstFlood, window }
  this.strikes = {}; // IP -> strike count
  this.bannedIPs = {}; // IP -> { bannedUntil, reason, permanent }

  // Statistics
  this.stats = {
    totalConnections: 0,
    totalMalformed: 0,
    totalFloods: 0,
    totalBans: 0,
    activeBans: 0,
  };

  /**
   * Check if an IP is currently banned
   * @param {string} ip - IP address to check
   * @returns {Object|null} Ban info if banned, null otherwise
   */
  this.isBanned = function (ip) {
    if (!_this.options.enabled || !_this.options.ban.enabled) {
      return null;
    }

    var ban = _this.bannedIPs[ip];
    if (!ban) return null;

    var now = Date.now();

    // Check if ban has expired
    if (!ban.permanent && now >= ban.bannedUntil) {
      delete _this.bannedIPs[ip];
      _this.stats.activeBans--;
      _this.emit("banExpired", ip);
      return null;
    }

    return {
      remainingTime: ban.permanent
        ? Infinity
        : Math.floor((ban.bannedUntil - now) / 1000),
      reason: ban.reason,
      permanent: ban.permanent,
    };
  };

  /**
   * Record a new connection attempt
   * @param {string} ip - IP address
   * @returns {boolean} True if connection allowed, false if rate limited
   */
  this.recordConnection = function (ip) {
    if (!_this.options.enabled || !_this.options.rateLimit.enabled) {
      return true;
    }

    _this.stats.totalConnections++;

    var now = Date.now();
    var record = _this.connectionCounts[ip];

    // Initialize or reset if outside window
    if (
      !record ||
      now - record.firstConnection > _this.options.rateLimit.window
    ) {
      _this.connectionCounts[ip] = {
        count: 1,
        firstConnection: now,
        window: _this.options.rateLimit.window,
      };
      return true;
    }

    // Increment counter
    record.count++;

    // Check if rate limit exceeded
    if (record.count > _this.options.rateLimit.maxConnections) {
      _this.emit("rateLimitExceeded", ip, "connection", record.count);
      _this.addStrike(ip, "Too many connections");
      return false;
    }

    return true;
  };

  /**
   * Record a malformed message from an IP
   * @param {string} ip - IP address
   * @param {string} message - The malformed message
   * @returns {boolean} True if should ban, false otherwise
   */
  this.recordMalformed = function (ip, message) {
    if (!_this.options.enabled || !_this.options.rateLimit.enabled) {
      return false;
    }

    _this.stats.totalMalformed++;

    var now = Date.now();
    var record = _this.malformedCounts[ip];

    // Initialize or reset if outside window
    if (!record || now - record.firstMessage > _this.options.rateLimit.window) {
      _this.malformedCounts[ip] = {
        count: 1,
        firstMessage: now,
        messages: [message],
        window: _this.options.rateLimit.window,
      };

      // First offense - just warn
      _this.emit("malformedMessage", ip, message, 1);
      return false;
    }

    // Increment counter
    record.count++;
    record.messages.push(message);

    _this.emit("malformedMessage", ip, message, record.count);

    // Check if threshold exceeded
    if (record.count >= _this.options.rateLimit.maxMalformed) {
      _this.addStrike(ip, "Too many malformed messages (" + record.count + ")");
      return true;
    }

    return false;
  };

  /**
   * Record a socket flood from an IP
   * @param {string} ip - IP address
   * @returns {boolean} True if should ban, false otherwise
   */
  this.recordFlood = function (ip) {
    if (!_this.options.enabled || !_this.options.rateLimit.enabled) {
      return false;
    }

    _this.stats.totalFloods++;

    var now = Date.now();
    var record = _this.floodCounts[ip];

    // Initialize or reset if outside window
    if (!record || now - record.firstFlood > _this.options.rateLimit.window) {
      _this.floodCounts[ip] = {
        count: 1,
        firstFlood: now,
        window: _this.options.rateLimit.window,
      };

      _this.emit("socketFlooded", ip, 1);
      return false;
    }

    // Increment counter
    record.count++;

    _this.emit("socketFlooded", ip, record.count);

    // Check if threshold exceeded
    if (record.count >= _this.options.rateLimit.maxFloods) {
      _this.addStrike(ip, "Socket flooding (" + record.count + " times)");
      return true;
    }

    return false;
  };

  /**
   * Add a strike to an IP address
   * @param {string} ip - IP address
   * @param {string} reason - Reason for the strike
   */
  this.addStrike = function (ip, reason) {
    if (!_this.options.enabled || !_this.options.ban.enabled) {
      return;
    }

    _this.strikes[ip] = (_this.strikes[ip] || 0) + 1;
    var strikeCount = _this.strikes[ip];

    _this.emit("strikeAdded", ip, reason, strikeCount);

    // Determine ban duration
    var banDuration;
    var permanent = false;

    if (strikeCount >= _this.options.ban.maxStrikes) {
      // Permanent ban
      banDuration = _this.options.ban.permanentDuration;
      permanent = true;
    } else {
      // Temporary ban, escalating duration
      banDuration = _this.options.ban.duration * strikeCount;
    }

    _this.banIP(ip, reason, banDuration, permanent);
  };

  /**
   * Ban an IP address
   * @param {string} ip - IP address to ban
   * @param {string} reason - Reason for ban
   * @param {number} duration - Ban duration in milliseconds
   * @param {boolean} permanent - Whether this is a permanent ban
   */
  this.banIP = function (ip, reason, duration, permanent) {
    if (!_this.options.enabled || !_this.options.ban.enabled) {
      return;
    }

    duration = duration || _this.options.ban.duration;
    permanent = permanent || false;

    var now = Date.now();
    var bannedUntil = permanent
      ? now + _this.options.ban.permanentDuration
      : now + duration;

    _this.bannedIPs[ip] = {
      bannedAt: now,
      bannedUntil: bannedUntil,
      reason: reason,
      permanent: permanent,
      strikes: _this.strikes[ip] || 0,
    };

    _this.stats.totalBans++;
    _this.stats.activeBans++;

    var durationSeconds = permanent
      ? Math.floor(_this.options.ban.permanentDuration / 1000)
      : Math.floor(duration / 1000);

    _this.emit("ipBanned", ip, reason, durationSeconds, permanent);
  };

  /**
   * Manually unban an IP address
   * @param {string} ip - IP address to unban
   */
  this.unbanIP = function (ip) {
    if (_this.bannedIPs[ip]) {
      delete _this.bannedIPs[ip];
      delete _this.strikes[ip];
      _this.stats.activeBans--;
      _this.emit("ipUnbanned", ip);
      return true;
    }
    return false;
  };

  /**
   * Get current statistics
   * @returns {Object} Statistics object
   */
  this.getStats = function () {
    return {
      totalConnections: _this.stats.totalConnections,
      totalMalformed: _this.stats.totalMalformed,
      totalFloods: _this.stats.totalFloods,
      totalBans: _this.stats.totalBans,
      activeBans: _this.stats.activeBans,
      currentlyBanned: Object.keys(_this.bannedIPs).length,
      tracked: {
        connections: Object.keys(_this.connectionCounts).length,
        malformed: Object.keys(_this.malformedCounts).length,
        floods: Object.keys(_this.floodCounts).length,
      },
    };
  };

  /**
   * Get list of currently banned IPs
   * @returns {Array} Array of banned IP objects
   */
  this.getBannedIPs = function () {
    var now = Date.now();
    var banned = [];

    for (var ip in _this.bannedIPs) {
      var ban = _this.bannedIPs[ip];
      banned.push({
        ip: ip,
        reason: ban.reason,
        bannedAt: ban.bannedAt,
        remainingTime: ban.permanent
          ? Infinity
          : Math.floor((ban.bannedUntil - now) / 1000),
        permanent: ban.permanent,
        strikes: ban.strikes,
      });
    }

    return banned;
  };

  /**
   * Clean up expired entries to prevent memory leaks
   */
  this.cleanup = function () {
    var now = Date.now();

    // Clean expired connection counts
    for (var ip in _this.connectionCounts) {
      if (
        now - _this.connectionCounts[ip].firstConnection >
        _this.options.rateLimit.window * 2
      ) {
        delete _this.connectionCounts[ip];
      }
    }

    // Clean expired malformed counts
    for (var ip in _this.malformedCounts) {
      if (
        now - _this.malformedCounts[ip].firstMessage >
        _this.options.rateLimit.window * 2
      ) {
        delete _this.malformedCounts[ip];
      }
    }

    // Clean expired flood counts
    for (var ip in _this.floodCounts) {
      if (
        now - _this.floodCounts[ip].firstFlood >
        _this.options.rateLimit.window * 2
      ) {
        delete _this.floodCounts[ip];
      }
    }

    // Check for expired bans
    for (var ip in _this.bannedIPs) {
      _this.isBanned(ip); // This will auto-remove expired bans
    }
  };

  // Run cleanup every 5 minutes
  setInterval(function () {
    _this.cleanup();
  }, 300000);
}

SecurityManager.prototype.__proto__ = events.EventEmitter.prototype;

module.exports = SecurityManager;
