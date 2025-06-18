package android.content.pm;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.ArraySet;

import java.security.PublicKey;

public class SigningDetails implements Parcelable {
    public SigningDetails(
            Signature[] signatures,
            int signatureSchemeVersion,
            ArraySet<PublicKey> keys,
            Signature[] pastSigningCertificates) {
        throw new RuntimeException("Stub!");
    }

    @Override
    public int describeContents() {
        throw new RuntimeException("Stub!");
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new RuntimeException("Stub!");
    }
}
