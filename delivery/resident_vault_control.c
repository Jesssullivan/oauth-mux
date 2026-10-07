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
int main(int argc,char **argv) {
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
