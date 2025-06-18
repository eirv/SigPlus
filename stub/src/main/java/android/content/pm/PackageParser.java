package android.content.pm;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.ArraySet;

import java.io.File;
import java.security.PublicKey;

public class PackageParser {
    public static final int PARSE_COLLECT_CERTIFICATES = 1 << 5;

    public static ApkLite parseApkLite(File apkFile, int flags) throws PackageParserException {
        throw new RuntimeException("Stub!");
    }

    public static class ApkLite {
        public final Signature[] signatures = null;
        public final VerifierInfo[] verifiers = null;
        public final SigningDetails signingDetails = null;
    }

    public static final class SigningDetails implements Parcelable {
        public final Signature[] signatures = null;
        public final int signatureSchemeVersion = Integer.parseInt(null);
        public final ArraySet<PublicKey> publicKeys = null;
        public final Signature[] pastSigningCertificates = null;

        @Override
        public int describeContents() {
            throw new RuntimeException("Stub!");
        }

        @Override
        public void writeToParcel(Parcel dest, int flags) {
            throw new RuntimeException("Stub!");
        }
    }

    public static class PackageParserException extends Exception {
    }
}
