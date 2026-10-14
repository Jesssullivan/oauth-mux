#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <gio/gio.h>
#include <fcntl.h>

#define FACTOR_MAX 4096
static unsigned char packet[FACTOR_MAX+12];
static uint64_t until;
static void wipe(void) { explicit_bzero(packet,sizeof(packet)); }
static uint64_t now(void) {
    struct timespec value; if (clock_gettime(CLOCK_MONOTONIC,&value)) return UINT64_MAX;
    return (uint64_t)value.tv_sec*1000000000ULL+(uint64_t)value.tv_nsec;
}
static int ready(int fd,short events) {
    for (;;) {
        uint64_t value=now(); if (value>=until) return 0;
        uint64_t left=(until-value+999999)/1000000;
        struct pollfd pollfd={fd,events,0};
        int result=poll(&pollfd,1,(int)(left>5000?5000:left));
        if (result<0 && errno==EINTR) continue;
        return result==1 && now()<until && (pollfd.revents&events)
            && !(pollfd.revents&(POLLERR|POLLNVAL));
    }
}
static void integer(unsigned char *out,uint32_t value) {
    out[0]=(unsigned char)(value>>24);out[1]=(unsigned char)(value>>16);
    out[2]=(unsigned char)(value>>8);out[3]=(unsigned char)value;
}
static int frame(size_t size) {
    if (!size || size>FACTOR_MAX || memchr(packet+12,0,size)) return 0;
    integer(packet,(uint32_t)size+12);
    integer(packet+4,1); /* GNOME48 GKD_CONTROL_OP_UNLOCK only. */
    integer(packet+8,(uint32_t)size);
    return 1;
}
static int exact(int fd,unsigned char *bytes,size_t length,int writing) {
    size_t offset=0;
    while (offset<length) {
        if (!ready(fd,writing?POLLOUT:POLLIN)) return 0;
        ssize_t count=writing?send(fd,bytes+offset,length-offset,MSG_NOSIGNAL|MSG_DONTWAIT):recv(fd,bytes+offset,length-offset,MSG_DONTWAIT);
        if (count<0 && (errno==EINTR||errno==EAGAIN)) continue;
        if (count<=0) return 0;
        offset+=(size_t)count;
    }
    return now()<until;
}
static int model(void) {
    const unsigned char wanted[]={0,0,0,15,0,0,0,1,0,0,0,3,0x61,0x62,0x63};
    memcpy(packet+12,"abc",3);
    if (!frame(3)||memcmp(packet,wanted,sizeof(wanted))) return 1;
    packet[13]=0;
    if (frame(3)||frame(0)||frame(FACTOR_MAX+1)) return 1;
    wipe();
    for (size_t i=0;i<sizeof(packet);i++) if (packet[i]) return 1;
    return 0;
}

/* Separate factor-free standard Secret Service action.  The legacy GNOME control
   mode below retains its original wire format and factor handling. */
#define STANDARD_ADDRESS "unix:path=/omux-resident-inputs/bus"
#define SECRET_PATH "/org/freedesktop/secrets"
#define SECRET_INTERFACE "org.freedesktop.Secret.Service"
typedef struct {
    guint32 broker_pid, manager_pid, secret_pid;
    unsigned long long broker_start, manager_start, secret_start;
    const char *manager_owner, *secret_owner, *collection;
} StandardWitness;
static const char *standard_status="identity-refused";
static char standard_collection[4096];
static void standard_clear(void) {explicit_bzero(standard_collection,sizeof(standard_collection));}
static int standard_result(void) {
    printf("{\"schema\":\"omux-standard-vault-unlock-result-v1\",\"status\":\"%s\"}\n",standard_status);
    return !strcmp(standard_status,"unlocked-for-client")?0:125;
}
static int standard_remaining(void) {
    uint64_t current=now(); if (current>=until) return 0;
    uint64_t left=(until-current+999999)/1000000;
    return (int)(left>5000?5000:left);
}
static int standard_number(const char *raw,unsigned long long *out) {
    if (!raw || !*raw || strlen(raw)>20) return 0;
    for (const char *p=raw;*p;p++) if (*p<'0'||*p>'9') return 0;
    errno=0; char *end=NULL; unsigned long long value=strtoull(raw,&end,10);
    if (errno || !end || *end || !value) return 0;
    *out=value; return 1;
}
static int standard_owner_name(const char *name) {
    if (!name || strlen(name)>128 || name[0]!=':') return 0;
    const char *p=name+1;
    if (!g_ascii_isdigit(*p)) return 0;
    while (g_ascii_isdigit(*p)) ++p;
    if (*p++!='.' || !g_ascii_isdigit(*p)) return 0;
    while (g_ascii_isdigit(*p)) ++p;
    return !*p;
}
static int standard_process(guint32 pid,unsigned long long wanted) {
    if (pid<=1 || !wanted || !standard_remaining()) return 0;
    char path[64],raw[8192];struct stat before,after;
    snprintf(path,sizeof(path),"/proc/%u",pid);
    if (stat(path,&before) || before.st_uid!=getuid()) return 0;
    snprintf(path,sizeof(path),"/proc/%u/stat",pid);
    FILE *file=fopen(path,"re"); if (!file) return 0;
    size_t count=fread(raw,1,sizeof(raw)-1,file);
    int ok=!ferror(file)&&feof(file);fclose(file);raw[count]=0;
    char *cursor=strrchr(raw,')');
    if (!ok || !cursor || cursor[1]!=' ') return 0;
    cursor+=2;
    for (int field=3;field<22;field++) {
        cursor=strchr(cursor,' '); if (!cursor) return 0; ++cursor;
    }
    if (!g_ascii_isdigit(*cursor)) return 0;
    errno=0;char *end=NULL;unsigned long long start=strtoull(cursor,&end,10);
    if (errno || end==cursor || (*end && *end!=' ') || start!=wanted) return 0;
    snprintf(path,sizeof(path),"/proc/%u",pid);
    return !stat(path,&after) && before.st_uid==after.st_uid && after.st_uid==getuid()
        && before.st_dev==after.st_dev && before.st_ino==after.st_ino && standard_remaining();
}
/* One bounded, private metadata pipe; never a factor file or terminal. */
static int standard_collection_input(void) {
    struct stat info;
    if(fstat(STDIN_FILENO,&info) || !S_ISFIFO(info.st_mode) || info.st_uid!=getuid()
        || (info.st_mode&0777)!=0600) return 0;
    int flags=fcntl(STDIN_FILENO,F_GETFL);
    if(flags<0 || fcntl(STDIN_FILENO,F_SETFL,flags|O_NONBLOCK)<0) return 0;
    atexit(standard_clear);size_t offset=0;
    for(;;) {
        int timeout=standard_remaining();if(!timeout){standard_status="deadline";return 0;}
        struct pollfd input={STDIN_FILENO,POLLIN,0};
        int result=poll(&input,1,timeout);
        if(result<0 && errno==EINTR)continue;
        if(result!=1 || !(input.revents&(POLLIN|POLLHUP)) || (input.revents&(POLLERR|POLLNVAL)))return 0;
        ssize_t count=read(STDIN_FILENO,standard_collection+offset,sizeof(standard_collection)-offset);
        if(count<0 && (errno==EINTR || errno==EAGAIN))continue;
        if(count<0)return 0;
        if(!count)break;
        offset+=(size_t)count;if(offset>=sizeof(standard_collection))return 0;
    }
    if(!offset || memchr(standard_collection,0,offset) || !standard_remaining())return 0;
    standard_collection[offset]=0;
    return strcmp(standard_collection,"/") && g_variant_is_object_path(standard_collection);
}
static GVariant *standard_call(GDBusConnection *bus,const char *destination,const char *path,
        const char *interface,const char *method,GVariant *arguments,const char *signature) {
    int left=standard_remaining();if (!left) {standard_status="deadline";return NULL;}
    GError *error=NULL;
    GVariant *reply=g_dbus_connection_call_sync(bus,destination,path,interface,method,arguments,
        G_VARIANT_TYPE(signature),G_DBUS_CALL_FLAGS_NO_AUTO_START,left,NULL,&error);
    if (error) g_error_free(error); /* Never publish OS error messages or paths. */
    if (!standard_remaining()) {if(reply)g_variant_unref(reply);standard_status="deadline";return NULL;}
    return reply;
}
static GVariant *standard_registry(GDBusConnection *bus,const char *method,const char *name,const char *signature) {
    return standard_call(bus,"org.freedesktop.DBus","/org/freedesktop/DBus",
        "org.freedesktop.DBus",method,g_variant_new("(s)",name),signature);
}
static int standard_owned(GDBusConnection *bus,const char *well_known,const char *wanted_owner,
        guint32 wanted_pid,unsigned long long wanted_start) {
    GVariant *reply=standard_registry(bus,"GetNameOwner",well_known,"(s)");
    if (!reply) return 0;
    const char *owner=NULL;g_variant_get(reply,"(&s)",&owner);
    int ok=owner && !strcmp(owner,wanted_owner);g_variant_unref(reply);
    const char *methods[]={"GetConnectionUnixUser","GetConnectionUnixProcessID"};
    guint32 values[2]={0,0};
    for (int i=0;ok && i<2;i++) {
        reply=standard_registry(bus,methods[i],wanted_owner,"(u)");
        if (!reply) return 0;
        g_variant_get(reply,"(u)",&values[i]);g_variant_unref(reply);
    }
    return ok && values[0]==getuid() && values[1]==wanted_pid && standard_process(wanted_pid,wanted_start);
}
static int standard_alias_locked(GDBusConnection *bus,const StandardWitness *witness,int *locked) {
    GVariant *reply=standard_call(bus,witness->secret_owner,SECRET_PATH,SECRET_INTERFACE,
        "ReadAlias",g_variant_new("(s)","default"),"(o)");
    if (!reply) return 0;
    const char *path=NULL;g_variant_get(reply,"(&o)",&path);
    int ok=path && !strcmp(path,witness->collection);g_variant_unref(reply);
    if (!ok) return 0;
    reply=standard_call(bus,witness->secret_owner,witness->collection,"org.freedesktop.DBus.Properties",
        "Get",g_variant_new("(ss)","org.freedesktop.Secret.Collection","Locked"),"(v)");
    if (!reply) return 0;
    GVariant *inner=NULL;g_variant_get(reply,"(v)",&inner);
    ok=inner && g_variant_is_of_type(inner,G_VARIANT_TYPE_BOOLEAN);
    if (ok) *locked=g_variant_get_boolean(inner);
    if (inner)g_variant_unref(inner);g_variant_unref(reply);return ok;
}
static int standard_identity(GDBusConnection *bus,const StandardWitness *witness) {
    GIOStream *stream=g_dbus_connection_get_stream(bus);
    if (!G_IS_SOCKET_CONNECTION(stream)) return 0;
    struct ucred peer={0};socklen_t length=sizeof(peer);
    int fd=g_socket_get_fd(g_socket_connection_get_socket(G_SOCKET_CONNECTION(stream)));
    return !getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length) && length==sizeof(peer)
        && peer.uid==getuid() && (guint32)peer.pid==witness->broker_pid
        && standard_process(witness->broker_pid,witness->broker_start)
        && standard_owned(bus,"org.freedesktop.systemd1",witness->manager_owner,witness->manager_pid,witness->manager_start)
        && standard_owned(bus,"org.freedesktop.secrets",witness->secret_owner,witness->secret_pid,witness->secret_start);
}
/* Exactly one requested collection; no foreign objects or duplicate results. */
static int standard_selected_paths(GVariant *paths,const char *collection,int allow_empty) {
    if (!paths || !g_variant_is_of_type(paths,G_VARIANT_TYPE("ao"))) return 0;
    gsize count=g_variant_n_children(paths);
    if (!count) return allow_empty;
    if (count!=1) return 0;
    GVariant *child=g_variant_get_child_value(paths,0);
    int ok=!strcmp(g_variant_get_string(child,NULL),collection);
    g_variant_unref(child);return ok;
}
typedef struct { const char *owner,*path,*collection;int done,dismissed,valid; } StandardPrompt;
static void standard_completed(GDBusConnection *connection,const gchar *sender,const gchar *path,
        const gchar *interface,const gchar *signal,GVariant *parameters,gpointer data) {
    (void)connection;StandardPrompt *state=data;
    if (state->done || !sender || strcmp(sender,state->owner) || strcmp(path,state->path)
        || strcmp(interface,"org.freedesktop.Secret.Prompt") || strcmp(signal,"Completed")
        || !g_variant_is_of_type(parameters,G_VARIANT_TYPE("(bv)"))) return;
    gboolean dismissed=FALSE;GVariant *result=NULL;
    g_variant_get(parameters,"(bv)",&dismissed,&result);
    state->dismissed=dismissed;state->valid=dismissed || standard_selected_paths(result,state->collection,0);
    state->done=1;if(result)g_variant_unref(result);
}
static int standard_wait_completed(GMainContext *context,StandardPrompt *prompt,uint64_t prompt_until) {
    while (!prompt->done && standard_remaining() && now()<prompt_until) {
        while (!prompt->done && standard_remaining() && now()<prompt_until
            && g_main_context_iteration(context,FALSE)) {}
        if(!prompt->done)g_usleep(1000);
    }
    return prompt->done && standard_remaining() && now()<prompt_until;
}
typedef struct {GDBusConnection *bus;int done;} StandardConnect;
static void standard_connected(GObject *source,GAsyncResult *result,gpointer data) {
    (void)source;StandardConnect *state=data;GError *error=NULL;
    state->bus=g_dbus_connection_new_for_address_finish(result,&error);
    if(error)g_error_free(error);state->done=1;
}
static GDBusConnection *standard_connect(GMainContext *context) {
    /* Async authentication is bounded by the original action deadline, too.
       On expiry the one-shot client exits; no subsequent action may use a late result. */
    StandardConnect *state=g_new0(StandardConnect,1);GCancellable *cancel=g_cancellable_new();
    g_dbus_connection_new_for_address(STANDARD_ADDRESS,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT|G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
        NULL,cancel,standard_connected,state);
    while (!state->done && standard_remaining()) {
        while (standard_remaining() && g_main_context_iteration(context,FALSE)) {}
        if(!state->done)g_usleep(1000);
    }
    if (!state->done) {
        g_cancellable_cancel(cancel);g_object_unref(cancel);
        standard_status="deadline";return NULL; /* state remains alive until this process exits. */
    }
    GDBusConnection *bus=state->bus;g_free(state);g_object_unref(cancel);return bus;
}
static int standard_unlock(int argc,char **argv) {
    standard_status="arguments";
    if (argc!=10 || !getenv("DBUS_SESSION_BUS_ADDRESS")
        || strcmp(getenv("DBUS_SESSION_BUS_ADDRESS"),STANDARD_ADDRESS)) return standard_result();
    unsigned long long numbers[6]={0},deadline=0;
    const int positions[]={2,3,5,6,8,9};
    for (int i=0;i<6;i++) if (!standard_number(argv[positions[i]],&numbers[i])) return standard_result();
    if (numbers[0]<=1 || numbers[0]>INT32_MAX || numbers[2]<=1 || numbers[2]>INT32_MAX
        || numbers[4]<=1 || numbers[4]>INT32_MAX || !standard_owner_name(argv[4])
        || !standard_owner_name(argv[7])) return standard_result();
    standard_status="deadline";
    if (!standard_number(getenv("OMUX_RESIDENT_ORIGINAL_DEADLINE_NS"),&deadline)
        || deadline>INT64_MAX || now()>=deadline || deadline-now()>1200000000000ULL) return standard_result();
    until=deadline;
    standard_status="collection-input-refused";
    if(!standard_collection_input())return standard_result();
    StandardWitness witness={(guint32)numbers[0],(guint32)numbers[2],(guint32)numbers[4],
        numbers[1],numbers[3],numbers[5],argv[4],argv[7],standard_collection};
    GMainContext *context=g_main_context_new();g_main_context_push_thread_default(context);
    standard_status="bus-unavailable";GDBusConnection *bus=standard_connect(context);
    int state=-1,ok=0;char *prompt_path=NULL;guint subscription=0;
    StandardPrompt prompt={witness.secret_owner,NULL,witness.collection,0,0,0};
    if (!bus) goto done;
    g_dbus_connection_set_exit_on_close(bus,FALSE);
    standard_status="identity-refused";
    if (!standard_identity(bus,&witness)) goto done;
    standard_status="collection-refused";
    if (!standard_alias_locked(bus,&witness,&state) || state!=1) goto done;
    GVariantBuilder requested;g_variant_builder_init(&requested,G_VARIANT_TYPE("ao"));
    g_variant_builder_add(&requested,"o",witness.collection);
    standard_status="unlock-refused";
    GVariant *reply=standard_call(bus,witness.secret_owner,SECRET_PATH,SECRET_INTERFACE,
        "Unlock",g_variant_new("(ao)",&requested),"(aoo)");
    if (!reply) goto done;
    GVariant *unlocked=NULL;const char *raw_prompt=NULL;
    g_variant_get(reply,"(@ao&o)",&unlocked,&raw_prompt);
    int immediate=standard_selected_paths(unlocked,witness.collection,0);
    int deferred=g_variant_n_children(unlocked)==0 && raw_prompt && strcmp(raw_prompt,"/")
        && strlen(raw_prompt)<=4095 && g_variant_is_object_path(raw_prompt);
    if (deferred)prompt_path=g_strdup(raw_prompt);
    int no_prompt=raw_prompt && !strcmp(raw_prompt,"/");
    g_variant_unref(unlocked);g_variant_unref(reply);
    if (!(immediate && no_prompt) && !deferred) goto done;
    if (deferred) {
        prompt.path=prompt_path;
        /* Subscription precedes Prompt, so immediate completion cannot be lost. */
        subscription=g_dbus_connection_signal_subscribe(bus,witness.secret_owner,"org.freedesktop.Secret.Prompt",
            "Completed",prompt_path,NULL,G_DBUS_SIGNAL_FLAGS_NONE,standard_completed,&prompt,NULL);
        standard_status="prompt-unavailable";
        reply=standard_call(bus,witness.secret_owner,prompt_path,"org.freedesktop.Secret.Prompt",
            "Prompt",g_variant_new("(s)",""),"()");
        if (!reply) goto done;
        g_variant_unref(reply);
        uint64_t prompt_until=now()+120000000000ULL;
        if(prompt_until>until)prompt_until=until;
        if (!standard_wait_completed(context,&prompt,prompt_until)) {
            /* Dismiss may race Completed, which invalidates the prompt object.
               Either outcome remains a timeout refusal; never report a late success. */
            if(standard_remaining()) {
                reply=standard_call(bus,witness.secret_owner,prompt_path,"org.freedesktop.Secret.Prompt",
                    "Dismiss",NULL,"()");
                if(reply)g_variant_unref(reply);
            }
            standard_status="prompt-timeout";goto done;
        }
        if (prompt.dismissed) {standard_status="cancelled";goto done;}
        if (!prompt.valid) {standard_status="prompt-result-refused";goto done;}
    }
    standard_status="identity-refused";
    if (!standard_identity(bus,&witness)) goto done;
    standard_status="collection-refused";
    if (!standard_alias_locked(bus,&witness,&state) || state!=0) goto done;
    standard_status="identity-refused";
    if (!standard_identity(bus,&witness)) goto done;
    if (!standard_remaining()) {standard_status="deadline";goto done;}
    standard_status="unlocked-for-client";ok=1;
done:
    if(subscription)g_dbus_connection_signal_unsubscribe(bus,subscription);
    /* Prompt lifetime belongs to this client connection.  Never claim another
       client (including the resident daemon) can use the wrapping key. */
    if(bus)g_object_unref(bus);g_free(prompt_path);
    g_main_context_pop_thread_default(context);g_main_context_unref(context);
    if(!ok && !standard_remaining())standard_status="deadline";
    standard_clear();return standard_result();
}
static gboolean standard_model_busy(gpointer data) {
    ++*(unsigned int *)data;return G_SOURCE_CONTINUE;
}
typedef struct {StandardPrompt *prompt;GVariant *parameters;} StandardLateModel;
static gboolean standard_model_late(gpointer data) {
    StandardLateModel *late=data;g_usleep(75000);
    standard_completed(NULL,late->prompt->owner,late->prompt->path,
        "org.freedesktop.Secret.Prompt","Completed",late->parameters,late->prompt);
    return G_SOURCE_REMOVE;
}
static int standard_model(void) {
    const char *collection="/org/freedesktop/secrets/collection/existing";
    GVariant *good=g_variant_ref_sink(g_variant_new_objv(&collection,1));
    const char *other="/org/freedesktop/secrets/collection/other";
    GVariant *foreign=g_variant_ref_sink(g_variant_new_objv(&other,1));
    GVariant *empty=g_variant_ref_sink(g_variant_new_objv(NULL,0));
    const char *twice[]={collection,collection};
    GVariant *duplicate=g_variant_ref_sink(g_variant_new_objv(twice,2));
    if(!standard_selected_paths(good,collection,0) || standard_selected_paths(foreign,collection,0)
        || standard_selected_paths(empty,collection,0) || !standard_selected_paths(empty,collection,1)
        || standard_selected_paths(duplicate,collection,0))return 1;
    StandardPrompt state={":1.3","/prompt/existing",collection,0,0,0};
    GVariant *completed=g_variant_ref_sink(g_variant_new("(bv)",FALSE,good));
    standard_completed(NULL,":1.4",state.path,"org.freedesktop.Secret.Prompt","Completed",completed,&state);
    if(state.done)return 2;
    standard_completed(NULL,state.owner,"/prompt/other","org.freedesktop.Secret.Prompt","Completed",completed,&state);
    if(state.done)return 3;
    standard_completed(NULL,state.owner,state.path,"org.freedesktop.Secret.Prompt","Completed",completed,&state);
    if(!state.done||!state.valid||state.dismissed)return 4;
    state.done=state.valid=state.dismissed=0;
    GVariant *cancel=g_variant_ref_sink(g_variant_new("(bv)",TRUE,g_variant_new_string("not-published")));
    standard_completed(NULL,state.owner,state.path,"org.freedesktop.Secret.Prompt","Completed",cancel,&state);
    if(!state.done||!state.valid||!state.dismissed)return 5;
    state.done=state.valid=state.dismissed=0;
    GVariant *wrong=g_variant_ref_sink(g_variant_new("(bv)",FALSE,foreign));
    standard_completed(NULL,state.owner,state.path,"org.freedesktop.Secret.Prompt","Completed",wrong,&state);
    if(!state.done||state.valid)return 6;
    /* A continuously ready queue cannot defeat the same production wait loop.
       Completion dispatched after its deadline is still a refusal. */
    GMainContext *context=g_main_context_new();unsigned int dispatched=0;
    state.done=state.valid=state.dismissed=0;until=now()+2000000000ULL;
    GSource *busy=g_idle_source_new();g_source_set_callback(busy,standard_model_busy,&dispatched,NULL);
    g_source_attach(busy,context);
    int waited=standard_wait_completed(context,&state,now()+50000000ULL);
    g_source_destroy(busy);g_source_unref(busy);
    if(waited || !dispatched)return 7;
    StandardLateModel late={&state,completed};
    GSource *late_source=g_idle_source_new();g_source_set_callback(late_source,standard_model_late,&late,NULL);
    g_source_attach(late_source,context);
    waited=standard_wait_completed(context,&state,now()+50000000ULL);
    g_source_destroy(late_source);g_source_unref(late_source);g_main_context_unref(context);
    if(waited || !state.done || !state.valid)return 8;
    g_variant_unref(good);g_variant_unref(foreign);g_variant_unref(empty);g_variant_unref(duplicate);
    g_variant_unref(completed);g_variant_unref(cancel);g_variant_unref(wrong);
    return 0;
}

int main(int argc,char **argv) {
    if (argc>=2 && !strcmp(argv[1],"--standard-secret-service-unlock")) return standard_unlock(argc,argv);
    if (argc==2 && !strcmp(argv[1],"--standard-model")) return standard_model();
    if (argc==2 && !strcmp(argv[1],"--model")) return model();
    /* Held connection selected by the metadata-qualified carrier; no pathname reconnect,
       subprocess, daemon startup, other opcode or discovery path exists in this client. */
    if (argc!=2 || strcmp(argv[1],"--existing-unlock-stdin")) return 125;
    const char *fd_text=getenv("OMUX_VAULT_HELD_CONTROL_FD"),*pid_text=getenv("OMUX_VAULT_EXPECTED_PID");
    const char *deadline=getenv("OMUX_RESIDENT_ORIGINAL_DEADLINE_NS");
    if (!fd_text||!pid_text||!deadline) return 125;
    for (const char *p=fd_text;*p;p++) if (*p<'0'||*p>'9') return 125;
    for (const char *p=pid_text;*p;p++) if (*p<'0'||*p>'9') return 125;
    for (const char *p=deadline;*p;p++) if (*p<'0'||*p>'9') return 125;
    if (!*fd_text||strlen(fd_text)>8||!*pid_text||strlen(pid_text)>10||!*deadline||strlen(deadline)>20) return 125;
    int fd=atoi(fd_text); unsigned long expected=strtoul(pid_text,NULL,10);until=strtoull(deadline,NULL,10);
    if (fd<3||expected<=1||expected>INT32_MAX||now()>=until||until-now()>1200000000000ULL) return 125;
    struct ucred peer; socklen_t length=sizeof(peer); struct stat input;
    if (getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length)||length!=sizeof(peer)
        ||peer.uid!=getuid()||(unsigned long)peer.pid!=expected || fstat(STDIN_FILENO,&input)
        ||!S_ISREG(input.st_mode)||input.st_uid!=getuid()||((input.st_mode&0777)!=0600 && (input.st_mode&0777)!=0400)
        ||input.st_nlink!=1||input.st_size<1||input.st_size>FACTOR_MAX) return 125;
    struct rlimit core={0,0};
    if (setrlimit(RLIMIT_CORE,&core)||prctl(PR_SET_DUMPABLE,0)||mlock(packet,sizeof(packet))) return 125;
    atexit(wipe);
    size_t size=(size_t)input.st_size; ssize_t count=pread(STDIN_FILENO,packet+12,size,0);
    struct stat after;
    int ok=count==(ssize_t)size && !fstat(STDIN_FILENO,&after)
        && input.st_dev==after.st_dev && input.st_ino==after.st_ino
        && input.st_uid==after.st_uid && input.st_gid==after.st_gid && input.st_mode==after.st_mode
        && input.st_nlink==after.st_nlink && input.st_size==after.st_size
        && input.st_mtim.tv_sec==after.st_mtim.tv_sec && input.st_mtim.tv_nsec==after.st_mtim.tv_nsec
        && input.st_ctim.tv_sec==after.st_ctim.tv_sec && input.st_ctim.tv_nsec==after.st_ctim.tv_nsec
        && frame(size) && now()<until;
    unsigned char credentials=0,reply[8]={0};
    if (ok) ok=exact(fd,&credentials,1,1) && exact(fd,packet,size+12,1);
    wipe();
    if (ok) ok=exact(fd,reply,sizeof(reply),0);
    const unsigned char wanted[8]={0,0,0,8,0,0,0,0};
    ok=ok && !memcmp(reply,wanted,sizeof(reply));
    munlock(packet,sizeof(packet));
    return ok?0:125;
}
