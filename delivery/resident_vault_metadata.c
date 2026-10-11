#define _GNU_SOURCE
#include <gio/gio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ADDRESS "unix:path=/omux-resident-inputs/bus"
#define LOGIN "/org/freedesktop/secrets/collection/login"
#define GNOME_EXE "/nix/store/x1199bxd4ia75dd1nmh0xnnpfzxz1785-gnome-keyring-48.0/bin/.gnome-keyring-daemon-wrapped"
static gint64 until;
static int standard_metadata;
static const char *predicate="observer-arguments";
static int refused(void) {
    /* Only source-literal predicate names; no errors, paths or owner data. */
    printf("{\"schema\":\"omux-vault-observer-refusal-v1\",\"predicate\":\"%s\"}\n",predicate);
    return 125;
}
typedef struct { guint32 uid, pid; unsigned long long start; char exe[4096]; } Identity;
static int remaining(void) {
    gint64 left = until - g_get_monotonic_time();
    return left <= 0 ? 0 : (int)(left > 5000000 ? 5000 : (left + 999)/1000);
}
/* Failure detail is private until the initial broker branch selects it. */
static const char *identity_predicate="observer-identity-pid";
static int identity(guint32 pid, Identity *out) {
    identity_predicate="observer-identity-pid";
    char path[64], raw[8192]; struct stat info;
    if (pid <= 1) return 0;
    snprintf(path,sizeof(path),"/proc/%u",pid);
    identity_predicate="observer-identity-proc-stat";
    if (stat(path,&info)) return 0;
    identity_predicate="observer-identity-proc-owner";
    if (info.st_uid != getuid()) return 0;
    snprintf(path,sizeof(path),"/proc/%u/stat",pid);
    identity_predicate="observer-identity-stat-open";
    FILE *file = fopen(path,"re");
    if (!file) return 0;
    size_t count = fread(raw,1,sizeof(raw)-1,file); int ok = !ferror(file) && feof(file);
    fclose(file); raw[count] = 0;
    char *cursor = strrchr(raw,')');
    identity_predicate="observer-identity-stat-read";
    if (!ok) return 0;
    identity_predicate="observer-identity-stat-delimiter";
    if (!cursor || cursor[1] != ' ') return 0;
    cursor += 2;
    identity_predicate="observer-identity-start-field";
    for (int field=3;field<22;field++) {
        cursor = strchr(cursor,' ');
        if (!cursor) return 0;
        ++cursor;
    }
    identity_predicate="observer-identity-start-value";
    char *end=NULL; out->start=strtoull(cursor,&end,10);
    if (end == cursor || !out->start || (*end && *end!=' ')) return 0;
    /* Standard local-service role is authenticated by peer/registry credentials.
       The legacy proprietary GNOME control mode retains its executable witness. */
    if (standard_metadata) {
        out->uid=getuid(); out->pid=pid;
        identity_predicate="observer-identity-deadline";
        return remaining();
    }
    snprintf(path,sizeof(path),"/proc/%u/exe",pid);
    identity_predicate="observer-identity-exe-readlink";
    ssize_t length = readlink(path,out->exe,sizeof(out->exe)-1);
    if (length <= 0 || length >= (ssize_t)sizeof(out->exe)-1) return 0;
    out->exe[length]=0;
    /* Publish only public immutable executable paths; no arbitrary process paths. */
    identity_predicate="observer-identity-exe-prefix";
    if (strncmp(out->exe,"/nix/store/",11) && strncmp(out->exe,"/usr/",5) && strncmp(out->exe,"/run/wrappers/bin/",18)) return 0;
    identity_predicate="observer-identity-exe-characters";
    for (const char *p=out->exe;*p;p++)
        if (!g_ascii_isalnum(*p) && !strchr("/+._-",*p)) return 0;
    out->uid=getuid(); out->pid=pid;
    identity_predicate="observer-identity-deadline";
    return remaining();
}
/* Pure scalar classification; never reflects peer values or syscall errors. */
static const char *broker_peer_header(int result, socklen_t size, const struct ucred *peer, uid_t uid) {
    if (result) return "observer-broker-peer-credentials";
    if (size!=sizeof(*peer)) return "observer-broker-peer-length";
    if (peer->uid!=uid) return "observer-broker-peer-uid";
    return NULL;
}
static GVariant *call(GDBusConnection *bus, const char *dest, const char *path,
                     const char *iface, const char *method, GVariant *args, const char *reply) {
    int timeout=remaining(); if (!timeout) return NULL;
    GError *error=NULL;
    GVariant *value=g_dbus_connection_call_sync(bus,dest,path,iface,method,args,
        G_VARIANT_TYPE(reply),G_DBUS_CALL_FLAGS_NO_AUTO_START,timeout,NULL,&error);
    if (error) g_error_free(error);
    return value;
}
static GVariant *registry(GDBusConnection *bus,const char *method,const char *name,const char *reply) {
    return call(bus,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus",
        method,g_variant_new("(s)",name),reply);
}
static char *owner(GDBusConnection *bus,const char *name) {
    GVariant *value=registry(bus,"GetNameOwner",name,"(s)");
    if (!value) return NULL;
    const char *raw=NULL; g_variant_get(value,"(&s)",&raw);
    char *result=NULL;
    if (raw && raw[0]==':' && strlen(raw)<128) {
        int safe=1;
        for (const char *p=raw+1;*p;p++) if (!g_ascii_isdigit(*p) && *p!='.') safe=0;
        if (safe) result=g_strdup(raw);
    }
    g_variant_unref(value); return result;
}
static int absent(GDBusConnection *bus,const char *name) {
    GVariant *value=registry(bus,"NameHasOwner",name,"(b)");
    if (!value) return 0;
    gboolean present=TRUE; g_variant_get(value,"(b)",&present); g_variant_unref(value);
    return !present;
}
static int owned(GDBusConnection *bus,const char *name,Identity *out) {
    const char *methods[]={"GetConnectionUnixUser","GetConnectionUnixProcessID"};
    guint32 values[2]={0,0};
    for (int i=0;i<2;i++) {
        GVariant *value=registry(bus,methods[i],name,"(u)");
        if (!value) return 0;
        g_variant_get(value,"(u)",&values[i]); g_variant_unref(value);
    }
    return values[0]==getuid() && identity(values[1],out);
}
static char *alias(GDBusConnection *bus,const char *name) {
    GVariant *value=call(bus,name,"/org/freedesktop/secrets","org.freedesktop.Secret.Service",
        "ReadAlias",g_variant_new("(s)","default"),"(o)");
    if (!value) return NULL;
    const char *raw=NULL; g_variant_get(value,"(&o)",&raw);
    char *result=raw && strlen(raw)<4096 ? g_strdup(raw) : NULL;
    g_variant_unref(value); return result;
}
static int locked(GDBusConnection *bus,const char *name,const char *path,int *out) {
    GVariant *value=call(bus,name,path,"org.freedesktop.DBus.Properties","Get",
        g_variant_new("(ss)","org.freedesktop.Secret.Collection","Locked"),"(v)");
    if (!value) return 0;
    GVariant *inner=NULL; g_variant_get(value,"(v)",&inner);
    int ok=inner && g_variant_is_of_type(inner,G_VARIANT_TYPE_BOOLEAN);
    if (ok) *out=g_variant_get_boolean(inner);
    if (inner) g_variant_unref(inner);
    g_variant_unref(value); return ok;
}
static void print_identity(const Identity *value,const char *name) {
    printf("{\"uid\":%u,\"pid\":%u,\"start_ticks\":%llu",
        value->uid,value->pid,value->start);
    if (!standard_metadata) printf(",\"exe\":\"%s\"",value->exe);
    if (name) printf(",\"owner\":\"%s\"",name);
    printf("}");
}
#ifndef OMUX_VAULT_BROKER_HEADER_MODEL
int main(int argc,char **argv) {
    standard_metadata=argc==2 && !strcmp(argv[1],"--standard-service-metadata");
    const char *address=getenv("DBUS_SESSION_BUS_ADDRESS");
    const char *deadline=getenv("OMUX_RESIDENT_ORIGINAL_DEADLINE_NS");
    if ((argc!=1 && !standard_metadata) || !address || strcmp(address,ADDRESS) || !deadline || !*deadline || strlen(deadline)>20) return refused();
    predicate="observer-deadline";
    for (const char *p=deadline;*p;p++) if (!g_ascii_isdigit(*p)) return refused();
    char *end=NULL; unsigned long long ns=strtoull(deadline,&end,10);
    if (!end || *end || ns>INT64_MAX || ns/1000>(unsigned long long)g_get_monotonic_time()+1200000000ULL) return refused();
    until=(gint64)(ns/1000); if (!remaining()) return refused();
    predicate="observer-bus-connect";
    GError *error=NULL;
    GDBusConnection *bus=g_dbus_connection_new_for_address_sync(address,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT|G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
        NULL,NULL,&error);
    if (error) g_error_free(error);
    if (!bus) return refused();
    predicate="observer-broker-stream-type";
    GIOStream *stream=g_dbus_connection_get_stream(bus); struct ucred peer={0};
    socklen_t size=sizeof(peer); Identity broker={0},manager={0},secret={0};
    int ok=G_IS_SOCKET_CONNECTION(stream);
    if (ok) {
        int fd=g_socket_get_fd(g_socket_connection_get_socket(G_SOCKET_CONNECTION(stream)));
        int result=getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size);
        const char *failure=broker_peer_header(result,size,&peer,getuid());
        if (failure) { predicate=failure; ok=0; }
        else {
            ok=identity(peer.pid,&broker);
            if (!ok) predicate=identity_predicate;
        }
    }
    if (ok) predicate="observer-manager-owner";
    char *manager_name=ok ? owner(bus,"org.freedesktop.systemd1") : NULL;
    if (manager_name) predicate="observer-manager-identity";
    ok=manager_name && owned(bus,manager_name,&manager);
    if (ok) predicate="observer-secret-owner";
    char *secret_name=ok ? owner(bus,"org.freedesktop.secrets") : NULL;
    int present=secret_name!=NULL, exists=0, login=0, state=-1, gnome=0;
    char *path=NULL;
    if (present) {
        predicate="observer-secret-identity";
        ok=owned(bus,secret_name,&secret);
        gnome=ok && !strcmp(secret.exe,GNOME_EXE);
        /* Identity/provider witness precedes any collection operation. */
        if (ok && (gnome || standard_metadata)) {
            predicate="observer-default-alias";
            path=alias(bus,secret_name); ok=path!=NULL;
            if (ok) {
                exists=strcmp(path,"/")!=0; login=!strcmp(path,LOGIN);
                if (exists) {
                    predicate="observer-collection-locked";
                    ok=locked(bus,secret_name,path,&state);
                }
            }
        }
    } else {
        if (ok) predicate="observer-secret-absence";
        ok=ok && absent(bus,"org.freedesktop.secrets");
    }
    if (ok) predicate="observer-owner-stability";
    Identity broker_after={0},manager_after={0},secret_after={0};
    char *manager_again=ok ? owner(bus,"org.freedesktop.systemd1") : NULL;
    char *secret_again=ok && present ? owner(bus,"org.freedesktop.secrets") : NULL;
    ok=ok && manager_again && !strcmp(manager_name,manager_again)
        && identity(broker.pid,&broker_after) && !memcmp(&broker,&broker_after,sizeof(broker))
        && owned(bus,manager_again,&manager_after) && !memcmp(&manager,&manager_after,sizeof(manager));
    if (present) ok=ok && secret_again && !strcmp(secret_name,secret_again)
        && owned(bus,secret_again,&secret_after) && !memcmp(&secret,&secret_after,sizeof(secret));
    else ok=ok && absent(bus,"org.freedesktop.secrets");
    if (ok && (gnome || (standard_metadata && present))) {
        predicate="observer-alias-stability";
        char *again=alias(bus,secret_name); int after=-1;
        ok=again && !strcmp(path,again) && (!exists || (locked(bus,secret_name,again,&after) && after==state));
        g_free(again);
    }
    if (ok) predicate="observer-deadline";
    if (ok && remaining()) {
        printf("{\"schema\":\"%s\",\"broker\":",standard_metadata
            ? "omux-existing-vault-metadata-v2" : "omux-existing-vault-metadata-v1"); print_identity(&broker,NULL);
        printf(",\"manager\":"); print_identity(&manager,manager_name);
        printf(",\"secret_service\":"); if (present) print_identity(&secret,secret_name); else printf("null");
        if (standard_metadata) {
            printf(",\"provider\":\"%s\",\"default_collection\":",present?"standard-secret-service":"absent");
            if (present) printf("\"%s\"",path); else printf("null");
            printf(",\"default_exists\":%s,\"locked\":",present?(exists?"true":"false"):"null");
        } else {
            printf(",\"provider\":\"%s\",\"default_exists\":%s,\"default_is_login\":%s,\"locked\":",
                !present?"absent":gnome?"gnome-keyring-48.0":"unqualified-existing-provider",
                gnome?(exists?"true":"false"):"null",gnome?(login?"true":"false"):"null");
        }
        if (state<0) printf("null"); else printf("%s",state?"true":"false");
        printf(",\"items_read\":false,\"secrets_read\":false,\"provider_invocation\":false}\n");
    } else ok=0;
    g_free(path);g_free(manager_name);g_free(secret_name);g_free(manager_again);g_free(secret_again);g_object_unref(bus);
    return ok?0:refused();
}
#else
/* Separate declared provider-free model binary; production accepts no model flag. */
int main(void) {
    struct ucred peer={.pid=2,.uid=1000,.gid=1000};
    if (broker_peer_header(0,sizeof(peer),&peer,1000)!=NULL) return 1;
    if (strcmp(broker_peer_header(-1,sizeof(peer),&peer,1000),"observer-broker-peer-credentials")) return 2;
    if (strcmp(broker_peer_header(0,sizeof(peer)-1,&peer,1000),"observer-broker-peer-length")) return 3;
    if (strcmp(broker_peer_header(0,sizeof(peer)+1,&peer,1000),"observer-broker-peer-length")) return 4;
    if (strcmp(broker_peer_header(0,sizeof(peer),&peer,1001),"observer-broker-peer-uid")) return 5;
    Identity value={0};
    if (identity(0,&value) || strcmp(identity_predicate,"observer-identity-pid")) return 6;
    if (identity(1,&value) || strcmp(identity_predicate,"observer-identity-pid")) return 7;
    return 0;
}
#endif
