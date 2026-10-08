package com.transferchain.cryptotests;

import android.content.Context;
import android.content.Intent;
import android.util.Base64;
import androidx.appcompat.app.AppCompatActivity;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.transferchain.hkdf.HKDF;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaPreferences;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class HKDFPluginTest {
    private ExecutorService pool;
    private TestCordova cordova;

    @Before public void setUp() {
        pool = Executors.newFixedThreadPool(2);
        cordova = new TestCordova(pool);
    }

    @After public void tearDown() throws Exception {
        pool.shutdown();
        assertTrue("Native work did not finish", pool.awaitTermination(60, TimeUnit.SECONDS));
    }

    private PluginResult call(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        // Reuse the native worker pool without initializing the plugin twice.
        if (plugin.cordova == null) plugin.privateInitialize("test", cordova, null, new CordovaPreferences());
        Capture callback = new Capture();
        assertTrue(plugin.execute(action, args, callback));
        assertTrue("Native callback timed out", callback.done.await(60, TimeUnit.SECONDS));
        assertEquals(1, callback.count);
        return callback.result;
    }

    private PluginResult ok(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        PluginResult result = call(plugin, action, args);
        assertEquals("Native operation rejected", PluginResult.Status.OK.ordinal(), result.getStatus());
        return result;
    }

    private void rejects(CordovaPlugin plugin, String action, JSONArray args, String code) throws Exception {
        PluginResult result = call(plugin, action, args);
        assertEquals(PluginResult.Status.ERROR.ordinal(), result.getStatus());
        JSONObject error = new JSONObject(result.getMessage());
        assertEquals(code, error.getString("code"));
        assertFalse(error.getString("message").isEmpty());
    }

    private static String binary(byte[] data) { return Base64.encodeToString(data, Base64.NO_WRAP); }
    private static byte[] data(PluginResult result) {
        assertEquals(PluginResult.MESSAGE_TYPE_ARRAYBUFFER, result.getMessageType());
        return Base64.decode(result.getMessage(), Base64.DEFAULT);
    }
    private static String hex(byte[] data) {
        StringBuilder out = new StringBuilder();
        for (byte value : data) out.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return out.toString();
    }
    private static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    private static JSONArray args(int length, byte[] salt, byte[] info) throws Exception {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        try {
            return new JSONArray().put(new JSONObject().put("keyLength", length))
                .put(binary(ikm)).put(binary(salt)).put(binary(info));
        } finally { Arrays.fill(ikm, (byte) 0); }
    }

    @Test public void rfc5869CaseOneAndEmptySaltInfo() throws Exception {
        HKDF plugin = new HKDF();
        byte[] salt = unhex("000102030405060708090a0b0c"), info = unhex("f0f1f2f3f4f5f6f7f8f9"), output = null;
        try {
            output = data(ok(plugin, "derive", args(42, salt, info)));
            assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", hex(output));
            Arrays.fill(output, (byte) 0);
            output = data(ok(plugin, "derive", args(42, new byte[0], new byte[0])));
            assertEquals("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", hex(output));
            assertEquals("000102030405060708090a0b0c", hex(salt));
            assertEquals("f0f1f2f3f4f5f6f7f8f9", hex(info));
        } finally {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(info, (byte) 0);
            if (output != null) Arrays.fill(output, (byte) 0);
        }
    }

    @Test public void invalidLengthsRejectBeforeDerivation() throws Exception {
        HKDF plugin = new HKDF();
        for (int length : new int[] {0, -1, 8161}) {
            rejects(plugin, "derive", args(length, new byte[0], new byte[0]), "INVALID_ARGUMENT");
        }
        JSONArray fractional = args(32, new byte[0], new byte[0]);
        fractional.getJSONObject(0).put("keyLength", 1.5);
        rejects(plugin, "derive", fractional, "INVALID_ARGUMENT");
    }

    @Test public void overlappingNativeRequestsKeepIndependentOutputs() throws Exception {
        HKDF plugin = new HKDF();
        plugin.privateInitialize("test", cordova, null, new CordovaPreferences());
        Capture first = new Capture(), second = new Capture();
        byte[] salt = unhex("000102030405060708090a0b0c"), info = unhex("f0f1f2f3f4f5f6f7f8f9"), one = null, two = null;
        try {
            assertTrue(plugin.execute("derive", args(42, salt, info), first));
            assertTrue(plugin.execute("derive", args(42, new byte[0], new byte[0]), second));
            assertTrue(first.done.await(10, TimeUnit.SECONDS));
            assertTrue(second.done.await(10, TimeUnit.SECONDS));
            assertEquals(1, first.count);
            assertEquals(1, second.count);
            assertEquals(PluginResult.Status.OK.ordinal(), first.result.getStatus());
            assertEquals(PluginResult.Status.OK.ordinal(), second.result.getStatus());
            one = data(first.result);
            two = data(second.result);
            assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", hex(one));
            assertEquals("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", hex(two));
            Arrays.fill(one, (byte) 0);
            assertEquals("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", hex(two));
        } finally {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(info, (byte) 0);
            if (one != null) Arrays.fill(one, (byte) 0);
            if (two != null) Arrays.fill(two, (byte) 0);
        }
    }

    private static class Capture extends CallbackContext {
        final CountDownLatch done = new CountDownLatch(1);
        volatile PluginResult result;
        volatile int count;
        Capture() { super("test", null); }
        @Override public synchronized void sendPluginResult(PluginResult value) {
            result = value;
            count++;
            done.countDown();
        }
    }

    private static class TestCordova implements CordovaInterface {
        final ExecutorService executor;
        TestCordova(ExecutorService executor) { this.executor = executor; }
        @Override public ExecutorService getThreadPool() { return executor; }
        @Override public Context getContext() { return InstrumentationRegistry.getInstrumentation().getTargetContext(); }
        @Override public AppCompatActivity getActivity() { return null; }
        @Override public void startActivityForResult(CordovaPlugin plugin, Intent intent, int code) { throw new UnsupportedOperationException(); }
        @Override public void setActivityResultCallback(CordovaPlugin plugin) { throw new UnsupportedOperationException(); }
        @Override public Object onMessage(String id, Object data) { return null; }
        @Override public void requestPermission(CordovaPlugin plugin, int code, String permission) { throw new UnsupportedOperationException(); }
        @Override public void requestPermissions(CordovaPlugin plugin, int code, String[] permissions) { throw new UnsupportedOperationException(); }
        @Override public boolean hasPermission(String permission) { return true; }
    }
}
