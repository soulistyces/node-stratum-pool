/**
 * @module varDiff
 * @description Variable difficulty adjustment for Stratum mining pools.
 * Automatically adjusts worker difficulty based on share submission rate.
 */

var events = require("events");

/**
 * Ring buffer implementation for storing time intervals between shares.
 * Used to calculate rolling average of share submission times.
 *
 * @class RingBuffer
 * @private
 * @param {number} maxSize - Maximum number of elements to store
 */

function RingBuffer(maxSize) {
  var data = [];
  var cursor = 0;
  var isFull = false;
  this.append = function (x) {
    if (isFull) {
      data[cursor] = x;
      cursor = (cursor + 1) % maxSize;
    } else {
      data.push(x);
      cursor++;
      if (data.length >= maxSize) {
        cursor = 0;
        isFull = true;
      }
    }
  };
  this.avg = function () {
    var sum = data.reduce(function (a, b) {
      return a + b;
    });
    return sum / (isFull ? maxSize : cursor);
  };
  this.size = function () {
    return isFull ? maxSize : cursor;
  };
  this.clear = function () {
    data = [];
    cursor = 0;
    isFull = false;
  };
}

/**
 * Truncates a number to a fixed amount of decimal places.
 *
 * @function toFixed
 * @private
 * @param {number} num - Number to truncate
 * @param {number} len - Number of decimal places
 * @returns {number} Truncated number
 */

function toFixed(num, len) {
  return parseFloat(num.toFixed(len));
}

/**
 * Clamps a value between min and max (inclusive).
 */
function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

/**
 * Resolves the effective value for a tunable varDiff setting: the
 * client's requested value if one was supplied and this port allows
 * miner-configurable overrides for that setting, clamped to the
 * operator-defined bounds; otherwise the port's own default.
 *
 * @param {number} [clientValue] - Value requested via password param, or a
 *   non-positive sentinel if none/invalid was supplied.
 * @param {number} portDefault - The port's configured default.
 * @param {Object} [configurableBounds] - {min, max} allowed range for
 *   this setting on this port; if omitted, overrides are disabled.
 */
function getEffectiveSetting(clientValue, portDefault, configurableBounds) {
  if (
    typeof clientValue !== "number" ||
    isNaN(clientValue) ||
    clientValue <= 0
  ) {
    return portDefault;
  }
  if (!configurableBounds) {
    return portDefault;
  }
  return clamp(clientValue, configurableBounds.min, configurableBounds.max);
}

/**
 * Variable difficulty controller for automatically adjusting miner difficulty.
 * Monitors share submission rate and adjusts difficulty to maintain target time between shares.
 *
 * @class varDiff
 * @extends {EventEmitter}
 * @param {number} port - Port number this vardiff instance manages
 * @param {Object} varDiffOptions - Variable difficulty configuration
 * @param {number} varDiffOptions.minDiff - Minimum allowed difficulty
 * @param {number} varDiffOptions.maxDiff - Maximum allowed difficulty
 * @param {number} varDiffOptions.targetTime - Target seconds between shares
 * @param {number} varDiffOptions.retargetTime - Seconds between difficulty adjustments
 * @param {number} varDiffOptions.variancePercent - Allowed variance from target time (%)
 * @param {Object} [varDiffOptions.minerConfigurable] - Per-setting {min, max}
 *   bounds a miner may override via tt=/rt=/vp= password params. Omitting a
 *   setting here (or the whole object) disables miner overrides for it.
 *
 * @fires varDiff#newDifficulty - When difficulty should be changed for a client
 */

var varDiff = (module.exports = function varDiff(port, varDiffOptions) {
  var _this = this;
  var configurable = varDiffOptions.minerConfigurable || {};

  /**
   * Manages variable difficulty for a connected client.
   * Monitors the client's share submission rate and adjusts difficulty accordingly.
   *
   * @method manageClient
   * @param {Object} client - Stratum client object to manage
   */

this.manageClient = function (client) {
    var stratumPort = client.socket.localPort;

    if (stratumPort != port) {
      console.error("Handling a client which is not of this vardiff?");
    }
    var options = varDiffOptions;

    var lastTs;
    var lastRtc;
    var timeBuffer;

    // Effective per-client settings, locked in at first submit (see
    // below) — fixed for the rest of the session since the RingBuffer's
    // size depends on them and can't be resized mid-flight.
    var effectiveTargetTime;
    var effectiveRetargetTime;
    var effectiveTMin;
    var effectiveTMax;

    client.on("submit", function () {
      var ts = (Date.now() / 1000) | 0;

      if (!lastRtc) {
        // By stratum protocol order (subscribe -> authorize -> submit),
        // any tt=/rt=/vp= password params are already parsed onto the
        // client by the time the first share arrives — safe to read here.
        effectiveTargetTime = getEffectiveSetting(
          client.customTargetTime,
          options.targetTime,
          configurable.targetTime
        );
        effectiveRetargetTime = getEffectiveSetting(
          client.customRetargetTime,
          options.retargetTime,
          configurable.retargetTime
        );
        var effectiveVariancePercent = getEffectiveSetting(
          client.customVariancePercent,
          options.variancePercent,
          configurable.variancePercent
        );

        var effectiveVariance =
          effectiveTargetTime * (effectiveVariancePercent / 100);
        effectiveTMin = effectiveTargetTime - effectiveVariance;
        effectiveTMax = effectiveTargetTime + effectiveVariance;

        var effectiveBufferSize = Math.max(
          1,
          Math.round(
            (effectiveRetargetTime / effectiveTargetTime) * 4
          )
        );

        lastRtc = ts - effectiveRetargetTime / 2;
        lastTs = ts;
        timeBuffer = new RingBuffer(effectiveBufferSize);
        return;
      }

      var sinceLast = ts - lastTs;
      timeBuffer.append(sinceLast);
      lastTs = ts;

      if (
        ts - lastRtc < effectiveRetargetTime &&
        timeBuffer.size() > 0
      ) {
        return;
      }

      lastRtc = ts;
      var avg = timeBuffer.avg();
      var ddiff = effectiveTargetTime / avg;

      // Effective floor: the higher of the port's configured minDiff and
      // the client's own md= request (if any), but never above the port's
      // maxDiff — prevents a bogus/abusive md= from creating a floor
      // higher than the ceiling, which would deadlock retargeting.
      var effectiveMinDiff = Math.min(
        Math.max(options.minDiff, client.minimumDifficulty || 0),
        options.maxDiff
      );

      if (avg > effectiveTMax && client.difficulty > effectiveMinDiff) {
        if (ddiff * client.difficulty < effectiveMinDiff) {
          ddiff = effectiveMinDiff / client.difficulty;
        }
      } else if (avg < effectiveTMin && client.difficulty < options.maxDiff) {
        var diffMax = options.maxDiff;
        if (ddiff * client.difficulty > diffMax) {
          ddiff = diffMax / client.difficulty;
        }
      } else {
        timeBuffer.clear();
        return;
      }

      var newDiff = toFixed(client.difficulty * ddiff, 8);
      timeBuffer.clear();
      _this.emit("newDifficulty", client, newDiff);
    });
  };
});

varDiff.prototype.__proto__ = events.EventEmitter.prototype;