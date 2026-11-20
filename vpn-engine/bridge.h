#ifndef FIREWALL_BRIDGE_H
#define FIREWALL_BRIDGE_H

#include <stdlib.h>
#include <jni.h>

struct FirewallCallbacks {
    JavaVM *vm;
    jobject service;
    jmethodID allow;
    jmethodID protect;
};

int firewall_allow(struct FirewallCallbacks *callback, int protocol,
        const char *local, int local_port, const char *remote, int remote_port);
int firewall_protect(struct FirewallCallbacks *callback, int fd);
void firewall_release(struct FirewallCallbacks *callback);

#endif
