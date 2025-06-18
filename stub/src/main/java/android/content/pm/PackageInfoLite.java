package android.content.pm;

import android.os.Parcel;
import android.os.Parcelable;

public class PackageInfoLite implements Parcelable {
    public static final Parcelable.Creator<PackageInfoLite> CREATOR = null;

    public String packageName;
    public VerifierInfo[] verifiers;

    public int describeContents() {
        throw new RuntimeException("Stub!");
    }

    public void writeToParcel(Parcel dest, int parcelableFlags) {
        throw new RuntimeException("Stub!");
    }
}
