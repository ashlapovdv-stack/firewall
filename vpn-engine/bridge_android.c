#include "bridge.h"
#include "_cgo_export.h"

static JNIEnv *get_env(struct FirewallCallbacks *callback, int *attached) {
    JNIEnv *env = NULL;
    jint status = (*callback->vm)->GetEnv(callback->vm, (void **) &env, JNI_VERSION_1_6);
    *attached = 0;
    if (status == JNI_EDETACHED) {
        if ((*callback->vm)->AttachCurrentThread(callback->vm, &env, NULL) != JNI_OK) {
            return NULL;
        }
        *attached = 1;
    } else if (status != JNI_OK) {
        return NULL;
    }
    return env;
}

static int finish_call(struct FirewallCallbacks *callback, JNIEnv *env,
        int attached, jboolean allowed) {
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        allowed = JNI_FALSE;
    }
    if (attached) (*callback->vm)->DetachCurrentThread(callback->vm);
    return allowed == JNI_TRUE;
}

int firewall_allow(struct FirewallCallbacks *callback, int protocol,
        const char *local, int local_port, const char *remote, int remote_port) {
    int attached;
    JNIEnv *env = get_env(callback, &attached);
    if (!env) return 0;
    jstring src = (*env)->NewStringUTF(env, local);
    jstring dst = src ? (*env)->NewStringUTF(env, remote) : NULL;
    jboolean allowed = JNI_FALSE;
    if (dst) {
        allowed = (*env)->CallBooleanMethod(env, callback->service, callback->allow,
                (jint) protocol, src, (jint) local_port, dst, (jint) remote_port);
    }
    if (src) (*env)->DeleteLocalRef(env, src);
    if (dst) (*env)->DeleteLocalRef(env, dst);
    return finish_call(callback, env, attached, allowed);
}

int firewall_protect(struct FirewallCallbacks *callback, int fd) {
    int attached;
    JNIEnv *env = get_env(callback, &attached);
    if (!env) return 0;
    jboolean allowed = (*env)->CallBooleanMethod(env, callback->service, callback->protect, (jint) fd);
    return finish_call(callback, env, attached, allowed);
}

void firewall_release(struct FirewallCallbacks *callback) {
    int attached;
    JNIEnv *env = get_env(callback, &attached);
    if (env) {
        (*env)->DeleteGlobalRef(env, callback->service);
        if (attached) (*callback->vm)->DetachCurrentThread(callback->vm);
    }
    free(callback);
}

JNIEXPORT jlong JNICALL Java_ru_firewall_NativeTunnel_open(JNIEnv *env, jclass type,
        jint fd, jint mtu, jobject policy) {
    (void) type;
    struct FirewallCallbacks *callback = calloc(1, sizeof(*callback));
    if (!callback) return 0;
    if ((*env)->GetJavaVM(env, &callback->vm) != JNI_OK) {
        free(callback);
        return 0;
    }

    jclass cls = (*env)->GetObjectClass(env, policy);
    callback->allow = (*env)->GetMethodID(env, cls, "allowFlow",
            "(ILjava/lang/String;ILjava/lang/String;I)Z");
    if (callback->allow) {
        callback->protect = (*env)->GetMethodID(env, cls, "protectSocket", "(I)Z");
    }
    (*env)->DeleteLocalRef(env, cls);
    if (!callback->allow || !callback->protect) {
        free(callback);
        return 0;
    }
    callback->service = (*env)->NewGlobalRef(env, policy);
    if (!callback->service) {
        free(callback);
        return 0;
    }
    uintptr_t result = firewall_start(fd, mtu, callback);
    if (!result) firewall_release(callback);
    return (jlong) result;
}

JNIEXPORT void JNICALL Java_ru_firewall_NativeTunnel_close(JNIEnv *env, jclass type, jlong handle) {
    (void) env;
    (void) type;
    firewall_stop((uintptr_t) handle);
}
