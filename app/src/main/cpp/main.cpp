#include <jni.h>
#include <string>
#include <sys/system_properties.h>

#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/signal.h>
#include <linux/prctl.h>
#include <sys/prctl.h>

#include <android/log.h>
#include "xhook/xhook.h"

#define LOG_TAG "KILL_JNI"
#define SECMAGIC 0xdeadbeef
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char *apkPath_;
static const char *repPath_;

int (*old_open)(const char *, int, mode_t);
int (*old_open64)(const char *, int, mode_t);
int (*old_openat)(int, const char*, int, mode_t);
int (*old_openat64)(int, const char*, int, mode_t);

#if defined(__aarch64__)
uint64_t OriSyscall(uint64_t num, uint64_t SYSARG_1, uint64_t SYSARG_2, uint64_t SYSARG_3,
                    uint64_t SYSARG_4, uint64_t SYSARG_5, uint64_t SYSARG_6) {
    uint64_t x0;
    __asm__ volatile (
            "mov x8, %1\n\t"
            "mov x0, %2\n\t"
            "mov x1, %3\n\t"
            "mov x2, %4\n\t"
            "mov x3, %5\n\t"
            "mov x4, %6\n\t"
            "mov x5, %7\n\t"
            "svc #0\n\t"
            "mov %0, x0\n\t"
            :"=r"(x0)
            :"r"(num), "r"(SYSARG_1), "r"(SYSARG_2), "r"(SYSARG_3), "r"(SYSARG_4), "r"(SYSARG_5), "r"(SYSARG_6)
            :"x8", "x0", "x1", "x2", "x3", "x4", "x4", "x5"
            );
    return x0;
}
#elif defined(__arm__)
uint32_t OriSyscall(uint32_t num, uint32_t SYSARG_1, uint32_t SYSARG_2, uint32_t SYSARG_3,
                    uint32_t SYSARG_4, uint32_t SYSARG_5, uint32_t SYSARG_6) {
    uint32_t x0;
    __asm__ volatile (
        "mov r7, %1\n\t"
        "mov r0, %2\n\t"
        "mov r1, %3\n\t"
        "mov r2, %4\n\t"
        "mov r3, %5\n\t"
        "mov r4, %6\n\t"
        "mov r5, %7\n\t"
        "svc #0\n\t"
        "mov %0, r0\n\t"
        :"=r"(x0)
        :"r"(num), "r"(SYSARG_1), "r"(SYSARG_2), "r"(SYSARG_3), "r"(SYSARG_4), "r"(SYSARG_5), "r"(SYSARG_6)
        :"r7", "r0", "r1", "r2", "r3", "r4", "r5"
    );
    return x0;
}
#endif

static const char* check_and_replace_path(const char* pathname) {
    if (pathname && strcmp(pathname, apkPath_) == 0) {
        return repPath_;
    }
    return pathname;
}

static int openImpl(const char *pathname, int flags, mode_t mode) {
    return old_open(check_and_replace_path(pathname), flags, mode);
}

static int open64Impl(const char *pathname, int flags, mode_t mode) {
    return old_open64(check_and_replace_path(pathname), flags, mode);
}

static int openatImpl(int fd, const char *pathname, int flags, mode_t mode) {
    return old_openat(fd, check_and_replace_path(pathname), flags, mode);
}

static int openat64Impl(int fd, const char *pathname, int flags, mode_t mode) {
    return old_openat64(fd, check_and_replace_path(pathname), flags, mode);
}

void sig_handler(int signo, siginfo_t *info, void *data) {
    ucontext_t *context = (ucontext_t *) data;
#if defined(__aarch64__)
    unsigned long syscall_number = context->uc_mcontext.regs[8];
    if (syscall_number == __NR_openat) {
        int fd = context->uc_mcontext.regs[0];
        const char *pathname = (const char *)context->uc_mcontext.regs[1];
        int flags = context->uc_mcontext.regs[2];
        mode_t mode = context->uc_mcontext.regs[3];

        pathname = check_and_replace_path(pathname);
        context->uc_mcontext.regs[0] = OriSyscall(__NR_openat, fd, (uint64_t)pathname, flags, mode, SECMAGIC, SECMAGIC);
    }
#elif defined(__arm__)
    unsigned long syscall_number = context->uc_mcontext.arm_r7;
    if (syscall_number == __NR_openat) {
        int fd = context->uc_mcontext.arm_r0;
        const char *pathname = (const char *)context->uc_mcontext.arm_r1;
        int flags = context->uc_mcontext.arm_r2;
        mode_t mode = context->uc_mcontext.arm_r3;

        pathname = check_and_replace_path(pathname);
        context->uc_mcontext.arm_r0 = OriSyscall(__NR_openat, fd, (uint32_t)pathname, flags, mode, SECMAGIC, SECMAGIC);
    }
#endif
}

void InitSeccompFilter() {
    struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 2),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECMAGIC, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP)
    };

    struct sock_fprog prog = {
            .filter = filter,
            .len = sizeof(filter) / sizeof(filter[0])
    };

    struct sigaction sa = {
            .sa_sigaction = sig_handler,
            .sa_flags = SA_SIGINFO
    };
    sigfillset(&sa.sa_mask);

    if (sigaction(SIGSYS, &sa, NULL) == -1) {
        return;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        return;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        return;
    }
}

const char * getSystemProperty(JNIEnv* env, const char* key) {
    jclass systemClass = env->FindClass("java/lang/System");
    jmethodID getPropertyMethod = env->GetStaticMethodID(systemClass, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;");
    jstring keyStr = env->NewStringUTF(key);
    auto value = (jstring) env->CallStaticObjectMethod(systemClass, getPropertyMethod, keyStr);
    const char *chars = env->GetStringUTFChars(value, nullptr);
    env->DeleteLocalRef(systemClass);
    env->DeleteLocalRef(value);
    return chars;
}

extern "C"
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {
    JNIEnv* env = nullptr;

    if (jvm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    LOGI("jni hook satrt...");
    apkPath_ = getSystemProperty(env, "mt.signature.killer.path1");
    repPath_ = getSystemProperty(env, "mt.signature.killer.path2");

    LOGI("mt.signature.killer.path1 = %s", apkPath_);
    LOGI("mt.signature.killer.path2 = %s", repPath_);

    xhook_register(".*\\.so$", "openat64", (void *)openat64Impl, (void **) &old_openat64);
    xhook_register(".*\\.so$", "openat", (void *)openatImpl, (void **) &old_openat);
    xhook_register(".*\\.so$", "open64", (void *)open64Impl, (void **) &old_open64);
    xhook_register(".*\\.so$", "open", (void *)openImpl, (void **) &old_open);
    xhook_refresh(0);

    LOGI("xhook start!");

    InitSeccompFilter();

    LOGI("svc hook start!");

    return JNI_VERSION_1_6;
}