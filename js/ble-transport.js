(function () {
  // ISO 18013-5 BLE transport
  // Exposes window.BLE with:
  //  init({ onAssembled, logger, defaultChunk })
  //  connect(serviceUUID)
  //  writeState(byte)
  //  sendFragmented(payload, chunkSize)
  //  disconnect()
  //  isConnected()

  const UUIDS = {
    state: "00000001-a123-48ce-896b-4c76973373e6",
    c2s: "00000002-a123-48ce-896b-4c76973373e6",
    s2c: "00000003-a123-48ce-896b-4c76973373e6",
  };

  let device = null,
    server = null,
    service = null;
  let chState = null,
    chC2S = null,
    chS2C = null;

  let rxBuffer = [];
  let rxTimer = null;
  let rxLastLen = 0;
  let rxStalledCount = 0;

  let onAssembled = null;
  let defaultChunk = 244;
  // Negotiated/effective chunk size discovered during the session
  let negotiatedChunkSize = null;
  let notificationsActive = false;
  let logger = (m) => {
    try {
      console.log(m);
    } catch {}
  };

  function log(m) {
    try {
      logger(m);
    } catch {
      console.log(m);
    }
  }

  function calcRxTimeout(len) {
    // Be more generous to avoid premature flush on slower links/devices
    if (!len || len < 8192) return 2000; // <8KB
    if (len < 24576) return 4000; // 8-24KB
    if (len < 65536) return 7000; // 24-64KB
    return 12000; // >=64KB
  }

  function resetRx() {
    try {
      if (rxTimer) clearTimeout(rxTimer);
    } catch {}
    rxTimer = null;
    rxBuffer = [];
    rxLastLen = 0;
    rxStalledCount = 0;
  }

  async function processAssembled(assembled, reason) {
    try {
      if (typeof onAssembled === "function")
        await onAssembled(assembled, reason);
      else
        log(`S→C complete (${reason || "unknown"}): ${assembled.length} bytes`);
    } catch (e) {
      console.warn("processAssembled failed", e);
    }
  }

  async function handleServer2Client(event) {
    const data = new Uint8Array(event.target.value.buffer);
    if (data.length === 0) return;
    const flag = data[0];
    const chunk = data.slice(1);
    rxBuffer.push(chunk);
    log(`S→C notify: flag=0x${flag.toString(16)} len=${chunk.length}`);

    try {
      if (rxTimer) clearTimeout(rxTimer);
    } catch {}
    const currentLen = rxBuffer.reduce((n, a) => n + a.length, 0);
    const timeoutMs = calcRxTimeout(currentLen);
    rxTimer = setTimeout(async () => {
      try {
        const pendingLen = rxBuffer.reduce((n, a) => n + a.length, 0);
        if (pendingLen > 0) {
          const assembled = new Uint8Array(pendingLen);
          let o = 0;
          for (const seg of rxBuffer) {
            assembled.set(seg, o);
            o += seg.length;
          }
          // Dry-run CBOR decode to detect incompleteness
          try {
            if (typeof CBOR !== "undefined") CBOR.decode(assembled);
          } catch (e) {
            const msg = e && e.message ? e.message : String(e);
            const incomplete =
              /insufficient data|unexpected end|not enough/i.test(msg);
            if (incomplete) {
              if (pendingLen === rxLastLen) rxStalledCount++;
              else {
                rxStalledCount = 0;
                rxLastLen = pendingLen;
              }
              log(
                `⏳ Timeout but CBOR incomplete; waiting (len=${pendingLen}, stalled=${rxStalledCount})`
              );
              try {
                if (rxTimer) clearTimeout(rxTimer);
              } catch {}
              rxTimer = setTimeout(async () => {
                try {
                  const plen2 = rxBuffer.reduce((n, a) => n + a.length, 0);
                  const a2 = new Uint8Array(plen2);
                  let o2 = 0;
                  for (const s of rxBuffer) {
                    a2.set(s, o2);
                    o2 += s.length;
                  }
                  try {
                    if (typeof CBOR !== "undefined") CBOR.decode(a2);
                    rxBuffer = [];
                    await processAssembled(a2, "timeout");
                  } catch (e2) {
                    const msg2 = e2 && e2.message ? e2.message : String(e2);
                    const incomplete2 =
                      /insufficient data|unexpected end|not enough/i.test(msg2);
                    if (incomplete2 && rxStalledCount < 5) {
                      rxStalledCount++;
                      log(
                        `⏳ Still incomplete; continuing (stalled=${rxStalledCount})`
                      );
                      return;
                    }
                    rxBuffer = [];
                    await processAssembled(a2, "timeout");
                  }
                } catch (inner) {
                  console.warn("Timeout(2) failed", inner);
                }
              }, Math.round(calcRxTimeout(pendingLen) * 1.5));
              return;
            }
          }
          rxBuffer = [];
          await processAssembled(assembled, "timeout");
        }
      } catch (e) {
        console.warn("Timeout flush failed:", e);
      }
    }, timeoutMs);

    if (flag === 0x00) {
      try {
        if (rxTimer) clearTimeout(rxTimer);
      } catch {}
      const total = rxBuffer.reduce((n, a) => n + a.length, 0);
      const assembled = new Uint8Array(total);
      let o = 0;
      for (const seg of rxBuffer) {
        assembled.set(seg, o);
        o += seg.length;
      }
      rxBuffer = [];
      await processAssembled(assembled, "final-flag");
    }
  }

  function withTimeout(promise, ms, label) {
    let timer;
    return Promise.race([
      promise.finally(() => {
        try {
          clearTimeout(timer);
        } catch {}
      }),
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`Timeout while ${label}`)),
          ms
        );
      }),
    ]);
  }
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function connect(serviceUUID) {
    if (!serviceUUID) throw new Error("Service UUID required");
    if (!navigator.bluetooth) throw new Error("Web Bluetooth not supported");

    log(`🔎 Requesting device for service ${serviceUUID}…`);
    device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [serviceUUID] }],
      optionalServices: [serviceUUID],
    });
    log(`Device selected: ${device.name || "(unnamed)"} (${device.id})`);

    device.addEventListener("gattserverdisconnected", () => {
      log("📱 Wallet disconnected from reader.");
      server = service = chState = chC2S = chS2C = null;
    });

    try {
      if (device?.gatt?.connected) {
        log("🔌 Closing previous GATT connection");
        device.gatt.disconnect();
        await sleep(200);
      }
    } catch {}

    const tryGatt = async (tries) => {
      for (let i = 0; i <= tries; i++) {
        try {
          log(`Connecting to ${device.name || "(unnamed)"}…`);
          server = await withTimeout(
            device.gatt.connect(),
            10000,
            "connecting to GATT"
          );
          log("✓ GATT connected");
          // Reset negotiated chunk for a fresh session
          negotiatedChunkSize = null;
          return;
        } catch (e) {
          log(`❌ ${e.message || e}${i < tries ? " — retrying…" : ""}`);
          if (typeof device.watchAdvertisements === "function") {
            try {
              log("📡 Watching advertisements for 2s…");
              await withTimeout(
                device.watchAdvertisements(),
                2000,
                "watchAdvertisements"
              );
            } catch {}
          }
          await sleep(600 * (i + 1));
        }
      }
      throw new Error("GATT connect failed");
    };

    await tryGatt(2);

    log("🔧 Getting primary service…");
    service = await withTimeout(
      server.getPrimaryService(serviceUUID),
      7000,
      "getting primary service"
    );
    log("✓ Primary service acquired");

    log("🔩 Getting characteristics (state, c2s, s2c)…");
    chState = await withTimeout(
      service.getCharacteristic(UUIDS.state),
      5000,
      "getting state characteristic"
    );
    chC2S = await withTimeout(
      service.getCharacteristic(UUIDS.c2s),
      5000,
      "getting c2s characteristic"
    );
    chS2C = await withTimeout(
      service.getCharacteristic(UUIDS.s2c),
      5000,
      "getting s2c characteristic"
    );
    log("✓ Characteristics ready");

    if (!notificationsActive) {
      log("🔔 Enabling notifications on s2c…");
      await withTimeout(
        chS2C.startNotifications(),
        5000,
        "starting notifications"
      );
      chS2C.addEventListener("characteristicvaluechanged", handleServer2Client);
      notificationsActive = true;
      log("GATT ready. Notifications enabled.");
    } else {
      // Avoid duplicate log spam if connect() was invoked twice rapidly
      log("GATT ready. Notifications enabled.");
    }
  }

  async function writeState(byte) {
    if (!chState) throw new Error("State characteristic not available");
    await chState.writeValueWithoutResponse(Uint8Array.of(byte));
    log(`State set to 0x${byte.toString(16)}`);
  }

  async function sendFragmented(payload, chunkSize) {
    if (!chC2S)
      throw new Error("Client-to-Server characteristic not available");
    if (!device?.gatt?.connected) throw new Error("Device not connected");
    const userSz = parseInt(chunkSize, 10);
    // Start with caller-provided size, or previously negotiated size, or default
    let currentChunk =
      (Number.isFinite(userSz) && userSz > 0
        ? userSz
        : negotiatedChunkSize || defaultChunk) | 0;
    if (currentChunk <= 0) currentChunk = 20;

    const MIN_CHUNK = 20; // ATT default usable payload when MTU=23

    let off = 0;
    while (off < payload.length) {
      const rem = payload.length - off;
      let take = Math.min(rem, currentChunk);

      // Attempt write; on failure, back off chunk size and retry this slice
      // until success or minimum size reached.
      // We only adjust for this session to avoid probing writes.
      while (true) {
        const isLast = take === rem;
        const frag = new Uint8Array(1 + take);
        frag[0] = isLast ? 0x00 : 0x01;
        frag.set(payload.slice(off, off + take), 1);
        try {
          await chC2S.writeValueWithoutResponse(frag);
          // Success: advance and cache negotiated size if we discovered smaller-than-default
          negotiatedChunkSize = Math.min(currentChunk, defaultChunk);
          log(
            `C→S write: flag=0x${frag[0].toString(
              16
            )} len=${take} (chunk=${currentChunk})`
          );
          off += take;
          break; // proceed to next outer-loop chunk
        } catch (e) {
          // Back off aggressively (halve) but respect a minimum
          const prev = currentChunk;
          currentChunk = Math.max(MIN_CHUNK, Math.floor(currentChunk / 2));
          if (currentChunk === prev) {
            // We're already at minimum; rethrow
            throw e;
          }
          take = Math.min(rem, currentChunk);
          log(
            `⚠️ write failed (${
              e && e.message ? e.message : e
            }); reducing chunk to ${currentChunk} and retrying`
          );
          // Tiny delay to avoid hammering the controller
          await new Promise((r) => setTimeout(r, 10));
          continue;
        }
      }
      if (off < payload.length) await new Promise((r) => setTimeout(r, 10));
    }
  }

  function _removeNotificationsListener() {
    try {
      if (chS2C)
        chS2C.removeEventListener(
          "characteristicvaluechanged",
          handleServer2Client
        );
    } catch {}
    try {
      if (chS2C && typeof chS2C.stopNotifications === "function") {
        chS2C.stopNotifications().catch(() => {});
      }
    } catch {}
    notificationsActive = false;
  }

  function disconnect() {
    try {
      _removeNotificationsListener();
      if (device?.gatt?.connected) {
        log("🔌 Disconnecting BLE…");
        device.gatt.disconnect();
      }
    } catch {}
    resetRx();
    negotiatedChunkSize = null;
    device = server = service = chState = chC2S = chS2C = null;
  }

  function isConnected() {
    return !!(device && device.gatt && device.gatt.connected);
  }

  function init(opts) {
    opts = opts || {};
    if (typeof opts.logger === "function") logger = opts.logger;
    if (typeof opts.onAssembled === "function") onAssembled = opts.onAssembled;
    if (opts.defaultChunk) defaultChunk = opts.defaultChunk | 0;
  }

  window.BLE = {
    UUIDS,
    init,
    connect,
    writeState,
    sendFragmented,
    disconnect,
    isConnected,
    _calcRxTimeout: calcRxTimeout,
    getNegotiatedChunkSize: () => negotiatedChunkSize || null,
  };
})();
