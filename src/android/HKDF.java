package com.transferchain.hkdf;

import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONObject;

/** RFC 5869 SHA-256. Each request owns its buffers and runs on Cordova's pool. */
public final class HKDF extends CordovaPlugin {
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callback) {
        if (!"derive".equals(action)) return false;

        try {
            cordova.getThreadPool().execute(() -> {
                byte[] ikm = null, salt = null, info = null, output = null;

                try {
                    if (args.length() != 4 || !(args.opt(0) instanceof JSONObject)) {
                        throw new IllegalArgumentException();
                    }

                    Object raw = args.getJSONObject(0).opt("keyLength");

                    if (!(raw instanceof Number)) throw new IllegalArgumentException();

                    double length = ((Number) raw).doubleValue();

                    if (!Double.isFinite(length) || length != Math.rint(length) || length < 1 || length > 8160) {
                        throw new IllegalArgumentException();
                    }

                    CordovaArgs binary = new CordovaArgs(args);

                    checkEncoded(binary, 1, 1048576);
                    checkEncoded(binary, 2, 65536);
                    checkEncoded(binary, 3, 65536);
                    ikm = binary.getArrayBuffer(1);
                    salt = binary.getArrayBuffer(2);
                    info = binary.getArrayBuffer(3);
                    output = derive(ikm, salt, info, (int) length);
                    // Cordova constructs its binary callback before our owned output is wiped.
                    callback.success(output);
                } catch (IllegalArgumentException error) {
                    fail(callback, "INVALID_ARGUMENT", "Invalid HKDF byte input or keyLength.");
                } catch (OutOfMemoryError error) {
                    fail(callback, "RESOURCE_LIMIT", "Insufficient memory for HKDF operation.");
                } catch (Exception error) {
                    fail(callback, "OPERATION_FAILED", "Native HKDF operation failed.");
                } finally {
                    wipe(ikm);
                    wipe(salt);
                    wipe(info);
                    wipe(output);
                }
            });
        } catch (RuntimeException error) {
            fail(callback, "OPERATION_FAILED", "Unable to schedule HKDF operation.");
        }

        return true;
    }

    /** Caller owns inputs/output; this method wipes only its extract/expand intermediates. */
    static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        if (ikm == null || ikm.length < 1 || ikm.length > 1048576 ||
            salt == null || salt.length > 65536 || info == null || info.length > 65536 ||
            length < 1 || length > 255 * 32) throw new IllegalArgumentException();

        byte[] effectiveSalt = salt.length == 0 ? new byte[32] : salt;
        byte[] prk = null, previous = new byte[0], output = new byte[length];
        boolean complete = false;

        try {
            Mac mac = Mac.getInstance("HmacSHA256");

            mac.init(new SecretKeySpec(effectiveSalt, "HmacSHA256"));
            prk = mac.doFinal(ikm);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            int offset = 0;

            // T(n) = HMAC(PRK, T(n-1) || info || n); the counter is one byte.
            // doFinal resets Mac to its initialized key, so no concatenation buffer is needed.
            for (int counter = 1; offset < length; counter++) {
                mac.update(previous);
                mac.update(info);
                mac.update((byte) counter);
                wipe(previous);
                previous = mac.doFinal();
                int count = Math.min(previous.length, length - offset);

                System.arraycopy(previous, 0, output, offset, count);
                offset += count;
            }

            complete = true;
            return output;
        } finally {
            wipe(prk);
            wipe(previous);
            if (effectiveSalt != salt) wipe(effectiveSalt);
            if (!complete) wipe(output);
            // Provider-owned Mac/SecretKeySpec copies are not directly erasable here.
        }
    }

    private static void wipe(byte[] bytes) {
        if (bytes != null) Arrays.fill(bytes, (byte) 0);
    }

    private static void checkEncoded(CordovaArgs args, int index, int maximum) {
        Object value = args.opt(index);

        // Cordova owns binary encoding. Bound its wire value before decoding so
        // direct bridge callers cannot request an unbounded allocation.
        if (!(value instanceof String) || ((String) value).length() > 4 * ((maximum + 2) / 3)) {
            throw new IllegalArgumentException();
        }
    }

    private static void fail(CallbackContext callback, String code, String message) {
        JSONObject result = new JSONObject();

        try {
            result.put("code", code);
            result.put("message", message);
        } catch (org.json.JSONException ignored) {
            callback.error("Native HKDF operation failed.");
            return;
        }

        callback.error(result);
    }
}
