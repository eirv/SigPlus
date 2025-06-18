package android.content.pm;

import android.os.Parcel;
import android.os.Parcelable;

public final class SigningInfo implements Parcelable {
    public static final Parcelable.Creator<SigningInfo> CREATOR = null;

    public SigningInfo() {
        throw new RuntimeException("Stub!");
    }

    public SigningInfo(SigningInfo orig) {
        throw new RuntimeException("Stub!");
    }

    public SigningInfo(SigningDetails signingDetails) {
        throw new RuntimeException("Stub!");
    }

    public SigningInfo(PackageParser.SigningDetails signingDetails) {
        throw new RuntimeException("Stub!");
    }

    public boolean hasMultipleSigners() {
        throw new RuntimeException("Stub!");
    }

    public boolean hasPastSigningCertificates() {
        throw new RuntimeException("Stub!");
    }

    public Signature[] getSigningCertificateHistory() {
        throw new RuntimeException("Stub!");
    }

    public Signature[] getApkContentsSigners() {
        throw new RuntimeException("Stub!");
    }

    public int describeContents() {
        throw new RuntimeException("Stub!");
    }

    public void writeToParcel(Parcel dest, int parcelableFlags) {
        throw new RuntimeException("Stub!");
    }
}
