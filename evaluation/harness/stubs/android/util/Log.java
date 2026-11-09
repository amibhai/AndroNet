package android.util;

/** Host-JVM stand-in for android.util.Log. Never packaged into the on-device dex. */
public final class Log {
    private Log() {}
    public static int v(String t, String m) { return 0; }
    public static int d(String t, String m) { return 0; }
    public static int i(String t, String m) { return 0; }
    public static int w(String t, String m) { return 0; }
    public static int e(String t, String m) { return 0; }
    public static int e(String t, String m, Throwable e) { return 0; }
}
