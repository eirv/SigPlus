#include <dlfcn.h>
#include <dobby.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <syscall.h>
#include <unistd.h>

#include <string>

#include "elf_img.h"

#define _uintval(p) reinterpret_cast<uintptr_t>(p)
#define _ptr(p) reinterpret_cast<void*>(p)
#define _align_up(x, n) (((x) + ((n)-1)) & ~((n)-1))
#define _align_down(x, n) ((x) & -(n))
#define _page_size 4096
#define _page_align(n) _align_up(static_cast<uintptr_t>(n), _page_size)
#define _ptr_align(x) \
    _ptr(_align_down(reinterpret_cast<uintptr_t>(x), _page_size))
#define _make_rwx(p, n)                                                 \
    ::mprotect(_ptr_align(p),                                           \
               _page_align(_uintval(p) + n) != _page_align(_uintval(p)) \
                   ? _page_align(n) + _page_size                        \
                   : _page_align(n),                                    \
               PROT_READ | PROT_WRITE | PROT_EXEC)

#define HOOK(ret, func, ...)             \
    static ret (*O_##func)(__VA_ARGS__); \
    static ret R_##func(__VA_ARGS__)
#define INLINE_HOOK(elf, func)                                  \
    void* F_##func = elf.getSymbAddress(#func);                 \
    if (F_##func)                                               \
        InlineHook(F_##func, reinterpret_cast<void*>(R_##func), \
                   reinterpret_cast<void**>(&O_##func));

#ifdef __LP64__
#define LIBART_PATH_R "/apex/com.android.art/lib64/libart.so"
#define LIBART_PATH_Q "/apex/com.android.runtime/lib64/libart.so"
#define LIBART_PATH "/system/lib64/libart.so"
#define LIBBINDER_PATH "/system/lib64/libbinder.so"
#else
#define LIBART_PATH_R "/apex/com.android.art/lib/libart.so"
#define LIBART_PATH_Q "/apex/com.android.runtime/lib/libart.so"
#define LIBART_PATH "/system/lib/libart.so"
#define LIBBINDER_PATH "/system/lib/libbinder.so"
#endif

#define CODE_TEST 0x114514

struct Parcel;

typedef struct RedItem {
    char* origin;
    char* redirect;
} RedItem;

JavaVM* jvm;
jclass native_class;
jmethodID transact_mid;

RedItem* red_items;
int red_item_count = 0;

void* target_binder;

void (*setHiddenApiExemptions)(JNIEnv*, jclass, jobjectArray) = nullptr;

bool red_initialized = false;

static bool InlineHook(void* address, void* replace, void** origin) {
    _make_rwx(address, _page_size);
    return DobbyHook(address, reinterpret_cast<dobby_dummy_func_t>(replace),
                     reinterpret_cast<dobby_dummy_func_t*>(origin)) ==
           RS_SUCCESS;
}

const char* Redirect(const char* pathname) {
    if (pathname) {
        for (int i = 0; i < red_item_count; ++i) {
            RedItem& item = red_items[i];
            if (strcasecmp(pathname, item.origin) == 0) {
                return item.redirect;
            }
        }
    }
    return pathname;
}

HOOK(int, __openat, int fd, const char* pathname, int flags, int mode) {
    return O___openat(fd, Redirect(pathname), flags, mode);
}

HOOK(int, openat, int fd, const char* pathname, int flags, int mode) {
    return O_openat(fd, Redirect(pathname), flags, mode);
}

HOOK(int, __open, const char* pathname, int flags, int mode) {
    return O___open(Redirect(pathname), flags, mode);
}

HOOK(int, open, const char* pathname, int flags, int mode) {
    return O_open(Redirect(pathname), flags, mode);
}

HOOK(int, fstatat, int dirfd, const char* pathname, struct stat* buf,
     int flags) {
    return O_fstatat(dirfd, Redirect(pathname), buf, flags);
}

HOOK(int, fstatat64, int dirfd, const char* pathname, struct stat* buf,
     int flags) {
    return O_fstatat64(dirfd, Redirect(pathname), buf, flags);
}

bool InitIORed() {
    if (red_initialized) return true;

    Dl_info info;
    dladdr(reinterpret_cast<void*>(fopen), &info);
    SandHook::ElfImg libc(info.dli_fname);
    INLINE_HOOK(libc, __openat);
    INLINE_HOOK(libc, openat);
    INLINE_HOOK(libc, __open);
    INLINE_HOOK(libc, open);
    INLINE_HOOK(libc, fstatat);
    INLINE_HOOK(libc, fstatat64);

    bool status = true;
    red_initialized = status;
    return status;
}

JNIEnv* GetEnv() {
    JNIEnv* env;
    jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (!env) {
        jvm->AttachCurrentThread(&env, nullptr);
    }
    return env;
}

HOOK(int32_t, transact, void* thiz, uint32_t code, const Parcel& data,
     Parcel* reply, uint32_t flags) {
    if (!target_binder && code == CODE_TEST) {
        target_binder = thiz;
    }
    if (thiz != target_binder) {
        return O_transact(thiz, code, data, reply, flags);
    }
    JNIEnv* env = GetEnv();
    jlong data_ptr = reinterpret_cast<jlong>(&data);
    jlong reply_ptr = reinterpret_cast<jlong>(reply);
    return env->CallStaticIntMethod(native_class, transact_mid, code, data_ptr,
                                    reply_ptr, flags);
}

jint SigPlusNative(JNIEnv* env, jclass, jint id, jobject content) {
    if (id == 0) {
        jobjectArray prefixes = reinterpret_cast<jobjectArray>(content);
        if (setHiddenApiExemptions) {
            setHiddenApiExemptions(env, native_class, prefixes);
            return 1;
        }
    } else if (id == 1) {
        jobjectArray objarr = reinterpret_cast<jobjectArray>(content);
        jstring orig =
            reinterpret_cast<jstring>(env->GetObjectArrayElement(objarr, 0));
        jstring red =
            reinterpret_cast<jstring>(env->GetObjectArrayElement(objarr, 1));
        if (!orig || !red) return JNI_FALSE;
        if (InitIORed()) {
            red_items = reinterpret_cast<RedItem*>(
                realloc(red_items, (red_item_count + 1) * sizeof(RedItem)));
            RedItem& item = red_items[red_item_count];
            const char* orig_cstr = env->GetStringUTFChars(orig, nullptr);
            const char* red_cstr = env->GetStringUTFChars(red, nullptr);
            item.origin = strdup(orig_cstr);
            item.redirect = strdup(red_cstr);
            env->ReleaseStringUTFChars(orig, orig_cstr);
            env->ReleaseStringUTFChars(red, red_cstr);
            red_item_count++;
            return 1;
        }
    } else if (id == 2) {
        transact_mid = env->GetStaticMethodID(native_class, "t", "(IJJI)I");
        SandHook::ElfImg libbinder(LIBBINDER_PATH);
        void* func = libbinder.getSymbAddress(
            "_ZN7android8BpBinder8transactEjRKNS_6ParcelEPS1_j");
        if (func)
            return InlineHook(func, reinterpret_cast<void*>(R_transact),
                              reinterpret_cast<void**>(&O_transact));
    } else if (id == 3) {
        jlong* longarr =
            env->GetLongArrayElements(reinterpret_cast<jlongArray>(content), 0);
        uint32_t code = static_cast<uint32_t>(longarr[0]);
        Parcel* data = reinterpret_cast<Parcel*>(longarr[1]);
        Parcel* reply = reinterpret_cast<Parcel*>(longarr[2]);
        uint32_t flags = static_cast<uint32_t>(longarr[3]);
        return O_transact(target_binder, code, *data, reply, flags);
    }
    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    jvm = vm;
    JNIEnv* env = GetEnv();

    char sdk_str[16];
    __system_property_get("ro.build.version.sdk", sdk_str);
    int sdk = atoi(sdk_str);

    SandHook::ElfImg libart(sdk >= 30   ? LIBART_PATH_R
                            : sdk == 29 ? LIBART_PATH_Q
                                        : LIBART_PATH);

    auto Throwable_nativeFillInStackTrace = reinterpret_cast<jobjectArray (*)(
        JNIEnv*, jclass)>(
        libart.getSymbAddress(
            "_ZN3artL32Throwable_nativeFillInStackTraceEP7_JNIEnvP7_jclass"));
    if (!Throwable_nativeFillInStackTrace) return JNI_ERR;

    jobjectArray backtrace = Throwable_nativeFillInStackTrace(env, nullptr);
    jsize len = env->GetArrayLength(backtrace);

    const char* name = "n";
    const char* signature = "(ILjava/lang/Object;)I";
    const JNINativeMethod methods[] = {{name, signature, (void*)SigPlusNative}};

    for (jsize i = 1; len > i; i++) {
        jobject element = env->GetObjectArrayElement(backtrace, i);
        native_class = reinterpret_cast<jclass>(element);
        if (!env->GetStaticMethodID(native_class, name, signature)) {
            env->ExceptionClear();
            native_class = nullptr;
        } else
            break;
    }

    env->DeleteLocalRef(backtrace);

    if (!native_class ||
        env->RegisterNatives(native_class, methods, 1) != JNI_OK) {
        return JNI_ERR;
    }

    native_class = reinterpret_cast<jclass>(env->NewGlobalRef(native_class));

    if (sdk >= 28) {
        setHiddenApiExemptions =
            reinterpret_cast<void (*)(JNIEnv*, jclass, jobjectArray)>(
                libart.getSymbAddress(
                    "_ZN3artL32VMRuntime_setHiddenApiExemptionsEP7_JNIEnvP7_"
                    "jclassP13_jobjectArray"));
    }

    return JNI_VERSION_1_6;
}
