package sig;

import android.annotation.SuppressLint;
import android.app.ActivityThread;
import android.app.PropertyInvalidatedCache;
import android.app.ResourcesManager;
import android.content.pm.ApplicationInfo;
import android.content.pm.IPackageManager;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageParser;
import android.content.pm.PackageParser.ApkLite;
import android.content.pm.PackageParser.PackageParserException;
import android.content.pm.Signature;
import android.content.pm.SigningDetails;
import android.content.pm.SigningInfo;
import android.content.pm.VerifierInfo;
import android.content.pm.VersionedPackage;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.ArrayMap;

import dalvik.system.BaseDexClassLoader;

import libcore.io.ClassPathURLStreamHandler;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class SigPlus implements InvocationHandler {
    private static final String PACKAGE_SERVICE = "package";
    private static final String DATA_DIR = "sigdata/";
    private static final int CODE_TEST = 0x114514;

    public static final Map<String, AppItem> sAppItems = new HashMap<>();
    private static boolean sIoRedInited;
    private static boolean sBinderHookInited;
    private static int sDataStartPosition;
    private static final Constructor<Parcel> sParcelCtor;
    private static boolean sBinderHookTestOk;

    static {
        System.loadLibrary("sigplus");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            setApiExemptions("");
        }
        Parcel data = Parcel.obtain();
        data.writeInterfaceToken(IPackageManager.class.getName());
        sDataStartPosition = data.dataPosition();
        data.recycle();
        try {
            sParcelCtor = Parcel.class.getDeclaredConstructor(Long.TYPE);
            sParcelCtor.setAccessible(true);
            extractOriginalApksAndReadSignatures();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private IBinder mOriginBinder;

    private SigPlus(IBinder origin) {
        mOriginBinder = origin;
    }

    public static void init() {
        initIORed();
        initBinderHook();
        resetAssets();
        resetResources();
    }

    public static boolean initIORed() {
        if (sIoRedInited) return true;
        for (AppItem appItem : sAppItems.values()) {
            sIoRedInited = redirectFile(appItem.sourceDir, appItem.targetFile.getPath());
            if (!sIoRedInited) break;
        }
        return sIoRedInited;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @SuppressLint("PrivateApi")
    public static boolean initBinderHook() {
        if (sBinderHookInited) return true;
        IBinder service = ServiceManager.getService(PACKAGE_SERVICE);
        try {
            if (!hookBpBinder()) {
                throw new RuntimeException("Failed to hook BpBinder");
            }
            testBinderHook(service);
            if (!sBinderHookTestOk) {
                throw new RuntimeException("WTF???");
            }
            sBinderHookInited = true;
        } catch (Throwable e) {
            e.printStackTrace();
            try {
                if (service instanceof Proxy) return true;
                IPackageManager packageManager = ActivityThread.getPackageManager();
                Object proxy =
                        Proxy.newProxyInstance(
                                null, new Class[] {IBinder.class}, new SigPlus(service));
                Field sCacheField = findField(ServiceManager.class, "sCache");
                Map<String, Object> sCache = (Map<String, Object>) sCacheField.get(null);
                sCache.remove(PACKAGE_SERVICE);
                sCache.put(PACKAGE_SERVICE, proxy);
                Class<?> ipmspClass =
                        Class.forName("android.content.pm.IPackageManager$Stub$Proxy");
                Field mRemoteField = findField(ipmspClass, "mRemote");
                if (packageManager instanceof Proxy) {
                    InvocationHandler handler = Proxy.getInvocationHandler(packageManager);
                    if (handler != null) {
                        Class<?> clazz = handler.getClass();
                        do {
                            for (Field field : clazz.getDeclaredFields()) {
                                field.setAccessible(true);
                                Object value = field.get(handler);
                                if (value == null) continue;

                                if (value == service) {
                                    field.set(handler, proxy);
                                    continue;
                                }
                                Class<?> type = value.getClass();
                                if (type == ipmspClass) {
                                    mRemoteField.set(value, proxy);
                                }
                            }
                            clazz = clazz.getSuperclass();
                        } while (clazz != Object.class);
                    }
                } else {
                    mRemoteField.set(packageManager, proxy);
                }
                sBinderHookInited = true;
            } catch (Throwable e2) {
                e2.printStackTrace();
            }
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Field sPackageInfoCacheField = findField(PackageManager.class, "sPackageInfoCache");
                PropertyInvalidatedCache<?, ?> sPackageInfoCache =
                        (PropertyInvalidatedCache<?, ?>) sPackageInfoCacheField.get(null);
                sPackageInfoCache.clear();
            }
        } catch (Exception ignored) {
        }
        return sBinderHookInited;
    }

    public static void resetAssets() {
        try {
            ResourcesManager resourcesManager = ResourcesManager.getInstance();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                Field mCachedApkAssetsField = findField(ResourcesManager.class, "mCachedApkAssets");
                ArrayMap<?, ?> mCachedApkAssets =
                        (ArrayMap<?, ?>) mCachedApkAssetsField.get(resourcesManager);
                mCachedApkAssets.clear();
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    public static void resetResources() {
        resetResources(false);
    }

    public static void resetResources(boolean includeDex) {
        try {
            ClassLoader classLoader = SigPlus.class.getClassLoader();
            if (!(classLoader instanceof BaseDexClassLoader)) return;

            BaseDexClassLoader loader = (BaseDexClassLoader) classLoader;
            Field pathListField = findField(BaseDexClassLoader.class, "pathList");
            Object pathList = pathListField.get(loader);
            Class<?> dexPathListClass = pathListField.getType();

            String[] elementFieldNames = {"dexElements", "nativeLibraryPathElements"};
            for (int i = 0; 2 > i; i++) {
                if (i == 1 && Build.VERSION.SDK_INT < Build.VERSION_CODES.M) break;

                Field elementsField = findField(dexPathListClass, elementFieldNames[i]);
                Object[] elements = (Object[]) elementsField.get(pathList);
                assert elements != null;
                Class<?> elementClass = elementsField.getType().getComponentType();
                assert elementClass != null;
                Field initializedField = findField(elementClass, "initialized");
                Field resField =
                        findField(
                                elementClass,
                                Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
                                        ? "urlHandler"
                                        : "zipFile");

                for (Object element : elements) {
                    if (i == 0 && includeDex) {
                        throw new UnsupportedOperationException("Not implemented");
                    }
                    if (!initializedField.getBoolean(element)) continue;
                    initializedField.setBoolean(element, false);
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        ClassPathURLStreamHandler urlHandler =
                                (ClassPathURLStreamHandler) resField.get(element);
                        if (urlHandler == null) continue;
                        urlHandler.close();
                        resField.set(element, null);
                    } else {
                        ZipFile zipFile = (ZipFile) resField.get(element);
                        if (zipFile == null) continue;
                        zipFile.close();
                        resField.set(element, null);
                    }
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    private static void extractOriginalApksAndReadSignatures() throws Exception {
        String myPackageName = ActivityThread.currentPackageName();
        int userId = Process.myUid() / 100000;
        IPackageManager packageManager = ActivityThread.getPackageManager();
        ApplicationInfo myAppInfo =
                Build.VERSION.SDK_INT >= 33
                        ? packageManager.getApplicationInfo(myPackageName, 0L, userId)
                        : packageManager.getApplicationInfo(myPackageName, 0, userId);

        String dataDir = myAppInfo.dataDir;
        String sourceDir = myAppInfo.sourceDir;
        long lastUpdateTime = new File(myAppInfo.sourceDir).lastModified();
        File sigPlusDataDir = new File(myAppInfo.dataDir, DATA_DIR);
        File timeFile = new File(sigPlusDataDir, "time");

        if (!sigPlusDataDir.exists()) {
            sigPlusDataDir.mkdirs();
        }
        if (!timeFile.exists()) {
            timeFile.createNewFile();
        }

        if (lastUpdateTime != timeFile.lastModified()) {
            for (File file : sigPlusDataDir.listFiles()) {
                if (!file.getName().endsWith(".apk")) continue;
                file.delete();
            }

            try (ZipFile zip = new ZipFile(sourceDir)) {
                Enumeration<? extends ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String entryName = entry.getName();
                    if (!entryName.startsWith(DATA_DIR)) continue;
                    File file = new File(dataDir, entryName);
                    InputStream in = zip.getInputStream(entry);
                    try (FileOutputStream out = new FileOutputStream(file)) {
                        byte[] buf = new byte[32 * 1024];
                        int len;
                        while ((len = in.read(buf)) != -1) {
                            out.write(buf, 0, len);
                        }
                    }
                    in.close();
                }
            }
            timeFile.setLastModified(lastUpdateTime);
        }

        for (File file : sigPlusDataDir.listFiles()) {
            String name = file.getName();
            if (!name.endsWith(".apk")) continue;
            String packageName = name.substring(0, name.length() - 4);
            ApplicationInfo appInfo =
                    Build.VERSION.SDK_INT >= 33
                            ? packageManager.getApplicationInfo(packageName, 0L, userId)
                            : packageManager.getApplicationInfo(packageName, 0, userId);
            AppItem appItem = new AppItem();
            appItem.sourceDir = appInfo.sourceDir;
            appItem.targetFile = file;
            readSignatures(appItem);
            sAppItems.put(packageName, appItem);
        }
    }

    public static void readSignatures(AppItem appItem) throws PackageParserException {
        ApkLite apk;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            apk =
                    PackageParser.parseApkLite(
                            appItem.targetFile, PackageParser.PARSE_COLLECT_CERTIFICATES);
            PackageParser.SigningDetails ppsd = apk.signingDetails;
            appItem.signatures = ppsd.signatures;
            if (Build.VERSION.SDK_INT >= 33) {
                SigningDetails signingDetails =
                        new SigningDetails(
                                ppsd.signatures,
                                ppsd.signatureSchemeVersion,
                                ppsd.publicKeys,
                                ppsd.pastSigningCertificates);
                appItem.signingInfo = new SigningInfo(signingDetails);
            } else {
                appItem.signingInfo = new SigningInfo(ppsd);
            }
        } else {
            apk = PackageParser.parseApkLite(appItem.targetFile, 1 << 8);
            appItem.signatures = apk.signatures;
        }
        appItem.verifiers = apk.verifiers;
    }

    private static Field findField(Class<?> clazz, String name) throws NoSuchFieldException {
        Field field = clazz.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    public static boolean setApiExemptions(String... prefixes) {
        return n(0, prefixes) != 0;
    }

    public static boolean redirectFile(String origin, String redirect) {
        return n(1, new Object[] {origin, redirect}) != 0;
    }

    /**
     * 原理：Inline Hook 目标: /system/lib(64)/libbinder.so
     * 符号：_ZN7android8BpBinder8transactEjRKNS_6ParcelEPS1_j
     */
    public static boolean hookBpBinder() {
        return n(2, null) != 0;
    }

    public static int transactBackup(int code, long dataPtr, long replyPtr, int flags) {
        return n(3, new long[] {code, dataPtr, replyPtr, flags});
    }

    public static native int n(int id, Object content);

    public static int t(int code, long dataPtr, long replyPtr, int flags) {
        return onNativeTransact(code, dataPtr, replyPtr, flags);
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if ("transact".equals(method.getName())) {
            return transact((int) args[0], (Parcel) args[1], (Parcel) args[2], (int) args[3]);
        }
        try {
            return method.invoke(mOriginBinder, args);
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        } catch (IllegalAccessException e) {
            throw new AssertionError();
        }
    }

    @SuppressLint("NewApi")
    private boolean transact(int code, Parcel data, Parcel reply, int flags_)
            throws RemoteException {
        int getPackageInfoCode = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? 3 : 2;
        int getPackageInfoVersionedCode = getPackageInfoCode + 1;
        boolean getPackageInfo = code == getPackageInfoCode;

        if (getPackageInfo
                || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                        && code == getPackageInfoVersionedCode)) {
            int dataPosition = data.dataPosition();
            data.setDataPosition(sDataStartPosition);
            String packageName;
            if (getPackageInfo) {
                packageName = data.readString();
            } else {
                VersionedPackage versionedPackage = VersionedPackage.CREATOR.createFromParcel(data);
                packageName = versionedPackage.getPackageName();
            }
            long flags =
                    Build.VERSION.SDK_INT >= 33
                            ? data.readLong()
                            : data.readInt();
            data.setDataPosition(dataPosition);

            boolean getSignatures = (flags & PackageManager.GET_SIGNATURES) != 0;
            boolean getSigningCertificates =
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                            && (flags & PackageManager.GET_SIGNING_CERTIFICATES) != 0;

            AppItem appItem = sAppItems.get(packageName);

            if (appItem != null && (getSignatures || getSigningCertificates)) {
                boolean status = mOriginBinder.transact(code, data, reply, flags_);
                reply.setDataSize(reply.dataSize());
                int replyFirstPosition = reply.dataPosition();
                reply.readException();
                reply.readInt();
                int replyPosition = reply.dataPosition();
                PackageInfo packageInfo = PackageInfo.CREATOR.createFromParcel(reply);

                if (getSignatures) {
                    packageInfo.signatures = appItem.signatures;
                }
                if (getSigningCertificates) {
                    packageInfo.signingInfo = appItem.signingInfo;
                }

                reply.setDataPosition(replyPosition);
                packageInfo.writeToParcel(reply, 0);
                reply.setDataPosition(replyFirstPosition);
                return status;
            }
        }
        return mOriginBinder.transact(code, data, reply, flags_);
    }

    public static int onNativeTransact(int code, long dataPtr, long replyPtr, int flags_) {
        if (code == CODE_TEST) {
            sBinderHookTestOk = true;
        }

        int getPackageInfoCode = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? 3 : 2;
        int getPackageInfoVersionedCode = getPackageInfoCode + 1;
        boolean getPackageInfo = code == getPackageInfoCode;

        if (getPackageInfo
                || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                        && code == getPackageInfoVersionedCode)) {
            Parcel data = obtainParcel(dataPtr);
            Parcel reply = obtainParcel(replyPtr);

            int dataPosition = data.dataPosition();
            data.setDataPosition(sDataStartPosition);
            String packageName;
            if (getPackageInfo) {
                packageName = data.readString();
            } else {
                VersionedPackage versionedPackage = VersionedPackage.CREATOR.createFromParcel(data);
                packageName = versionedPackage.getPackageName();
            }
            long flags =
                    Build.VERSION.SDK_INT >= 33
                            ? data.readLong()
                            : data.readInt();
            data.setDataPosition(dataPosition);

            boolean getSignatures = (flags & PackageManager.GET_SIGNATURES) != 0;
            boolean getSigningCertificates =
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                            && (flags & PackageManager.GET_SIGNING_CERTIFICATES) != 0;

            AppItem appItem = sAppItems.get(packageName);

            if (appItem != null && (getSignatures || getSigningCertificates)) {
                int status = transactBackup(code, dataPtr, replyPtr, flags_);
                reply.setDataSize(reply.dataSize());
                int replyFirstPosition = reply.dataPosition();
                reply.readException();
                reply.readInt();
                int replyPosition = reply.dataPosition();
                PackageInfo packageInfo = PackageInfo.CREATOR.createFromParcel(reply);

                if (getSignatures) {
                    packageInfo.signatures = appItem.signatures;
                }
                if (getSigningCertificates) {
                    packageInfo.signingInfo = appItem.signingInfo;
                }

                reply.setDataPosition(replyPosition);
                packageInfo.writeToParcel(reply, 0);
                reply.setDataPosition(replyFirstPosition);
                return status;
            }
        }
        return transactBackup(code, dataPtr, replyPtr, flags_);
    }

    private static Parcel obtainParcel(long pointer) {
        try {
            return sParcelCtor.newInstance(pointer);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static void testBinderHook(IBinder service) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            service.transact(CODE_TEST, data, reply, 0);
        } catch (RemoteException ignored) {
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    public static class AppItem {
        public String sourceDir;
        public File targetFile;
        public Signature[] signatures;
        public SigningInfo signingInfo;
        public VerifierInfo[] verifiers;
    }
}
