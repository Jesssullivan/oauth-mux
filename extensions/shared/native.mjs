import { AcquisitionError, NATIVE_HOST, makeHealthEnvelope, validateHealthResponse } from "./protocol.mjs";

export function sendNativeRequest(api, envelope, { timeoutMs = 10000, setTimer = setTimeout, clearTimer = clearTimeout, healthEnvelope } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) return Promise.reject(new AcquisitionError("invalid_native_timeout"));
  return new Promise((resolve, reject) => {
    let port;
    let timer;
    let settled = false;
    let awaitingHealth = healthEnvelope !== undefined;
    const finish = (error, response) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimer(timer);
      port?.onMessage.removeListener(onMessage);
      port?.onDisconnect.removeListener(onDisconnect);
      // Disconnect closes native-host transport; source actions are idempotent
      // if the daemon committed before a response/transport timeout was seen.
      if (port) {
        try { port.disconnect(); } catch { /* A disconnected port needs no cleanup. */ }
      }
      if (error) reject(error);
      else resolve(response);
    };
    const onMessage = response => {
      if (settled) return;
      if (!awaitingHealth) return finish(null, response);
      try {
        validateHealthResponse(response, healthEnvelope.id);
      } catch (error) {
        finish(error instanceof AcquisitionError ? error : new AcquisitionError("invalid_native_response"));
        return;
      }
      awaitingHealth = false;
      try { port.postMessage(envelope); }
      catch { finish(new AcquisitionError("native_host_unavailable")); }
    };
    const onDisconnect = () => {
      // Read lastError to suppress browser diagnostics, never copy its message.
      void api.runtime.lastError;
      finish(new AcquisitionError("native_host_unavailable"));
    };
    try {
      port = api.runtime.connectNative(NATIVE_HOST);
      port.onMessage.addListener(onMessage);
      port.onDisconnect.addListener(onDisconnect);
      timer = setTimer(() => finish(new AcquisitionError("native_host_unavailable")), timeoutMs);
      // One native host and one overall deadline bind channel qualification to
      // this mutation's transport; no mutation is posted after failed health.
      port.postMessage(healthEnvelope ?? envelope);
    } catch {
      finish(new AcquisitionError("native_host_unavailable"));
    }
  });
}

export async function requestNativeHealth(api, browserKind, requestId, options) {
  const envelope = makeHealthEnvelope(requestId, { browser: browserKind, extensionId: api.runtime.id });
  const response = await sendNativeRequest(api, envelope, options);
  return validateHealthResponse(response, requestId);
}
