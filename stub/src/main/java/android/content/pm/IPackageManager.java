package android.content.pm;

import android.os.IInterface;

public interface IPackageManager extends IInterface {
    ApplicationInfo getApplicationInfo(String packageName, long flags, int userId);

    ApplicationInfo getApplicationInfo(String packageName, int flags, int userId);
}
