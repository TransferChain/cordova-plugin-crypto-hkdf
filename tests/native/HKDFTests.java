package com.transferchain.hkdf;

import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.cordova.CallbackContext;
import org.json.JSONArray;
import org.json.JSONObject;

/** RFC5869 public fixtures against production javax.crypto implementation. */
public final class HKDFTests {
    private static byte[] hex(String value) { return HexFormat.of().parseHex(value); }
    private static void check(boolean value) {
        if (!value) throw new AssertionError("HKDF fixture failed");
    }
    private static byte[] sequence(int start, int length) {
        byte[] result = new byte[length];
        for (int index = 0; index < length; index++) result[index] = (byte) (start + index);
        return result;
    }
    private static void vector(byte[] ikm, byte[] salt, byte[] info, String expected) throws Exception {
        byte[] before = ikm.clone(), output = null;
        try {
            output = HKDF.derive(ikm, salt, info, expected.length() / 2);
            check(Arrays.equals(output, hex(expected)));
            check(Arrays.equals(before, ikm));
        } finally {
            Arrays.fill(before, (byte) 0);
            if (output != null) Arrays.fill(output, (byte) 0);
        }
    }
    public static void main(String[] args) throws Exception {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 11);
        byte[] salt = sequence(0, 13), info = sequence(240, 10);
        String one = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        vector(ikm, salt, info, one);
        vector(sequence(0, 80), sequence(96, 80), sequence(176, 80),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
        vector(ikm, new byte[0], new byte[0],
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
        for (int length : new int[] {1, 32, 8160}) {
            byte[] output = HKDF.derive(ikm, salt, info, length);
            check(output.length == length);
            check(output[0] == hex(one)[0]);
            Arrays.fill(output, (byte) 0);
        }
        for (int length : new int[] {0, -1, 8161}) {
            boolean rejected = false;
            try { HKDF.derive(ikm, salt, info, length); }
            catch (IllegalArgumentException expected) { rejected = true; }
            check(rejected);
        }
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            var first = pool.submit(() -> HKDF.derive(ikm, salt, info, 42));
            var second = pool.submit(() -> HKDF.derive(ikm, salt, info, 42));
            byte[] left = first.get(5, TimeUnit.SECONDS), right = second.get(5, TimeUnit.SECONDS);
            check(left != right && Arrays.equals(left, right));
            Arrays.fill(left, (byte) 0);
            check(Arrays.equals(right, hex(one)));
            Arrays.fill(right, (byte) 0);
            HKDF plugin = new HKDF();
            plugin.cordova = () -> pool;
            for (Object length : new Object[] {0, 8161, 1.5, true, "32"}) {
                CallbackContext callback = new CallbackContext();
                check(plugin.execute("derive", new JSONArray()
                    .put(new JSONObject().put("keyLength", length))
                    .put(Base64.getEncoder().encodeToString(ikm)).put("").put(""), callback));
                check(callback.done.await(5, TimeUnit.SECONDS));
                check(callback.failure instanceof JSONObject);
                check(((JSONObject) callback.failure).getString("code").equals("INVALID_ARGUMENT"));
            }
        } finally {
            pool.shutdownNow();
            Arrays.fill(ikm, (byte) 0);
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(info, (byte) 0);
        }
        System.out.println("PASS HKDF RFC5869 cases1/2/3; bounds; caller ownership; two-operation isolation; bridge invalid types");
    }
}
