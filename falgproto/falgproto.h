/* vim: set sw=4 ts=4 sts=4 et: */
#ifndef FALGPROTO_H
#define FALGPROTO_H

#include <stdbool.h>
#include <stdio.h>

typedef enum falgproto_type {
    FALGPROTO_TYPE_HTTP,
    FALGPROTO_TYPE_HTTPS,
    FALGPROTO_TYPE_DNS,
    FALGPROTO_TYPE_FTP,
    FALGPROTO_TYPE_SSH,
    FALGPROTO_TYPE_LDAP,
    FALGPROTO_TYPE_MAX
} FalgprotoType;

typedef enum falgproto_transport {
    FALGPROTO_TRANSPORT_TCP,
    FALGPROTO_TRANSPORT_UDP
} FalgprotoTransport;

typedef struct falgproto_packet {
    struct falgproto_packet* next;
    void*   data;       /* unused (may be used by caller to store data) */
    char*   payload;    /* packet payload */
    size_t  len;        /* packet payload length */
} FalgprotoPacket;

typedef struct falgproto_param {
    char*   param;      /* parameter (may not be NULL-terminated) */
    size_t  len;        /* parameter length */
    bool    dup;        /* whether the parameter is malloc()-ed */
    int     result;     /* error code listed below */
} FalgprotoParam;

#define FALGPROTO_PARAM_RESULT_ERROR       -1
#define FALGPROTO_PARAM_RESULT_OK           0
#define FALGPROTO_PARAM_RESULT_NOT_FOUND    1
#define FALGPROTO_PARAM_RESULT_TRUNCATED    2

typedef FalgprotoParam (*FalgprotoParamGetter) (FalgprotoPacket *pkt);
typedef void     (*FalgprotoPrinter) (FILE *fp, FalgprotoPacket *pkt);
typedef bool     (*FalgprotoMatcher) (
    const char *big, size_t big_len, const char *little, size_t little_len);

#define FALGPROTO_PARAM_GETTER_NAME(type)   falgproto_##type##_param_getter
#define FALGPROTO_PARAM_GETTER_DECL(type) \
    FalgprotoParam FALGPROTO_PARAM_GETTER_NAME(type)(FalgprotoPacket *pkt)
#define FALGPROTO_PRINTER_NAME(type)        falgproto_##type##_printer
#define FALGPROTO_PRINTER_DECL(type) \
    void FALGPROTO_PRINTER_NAME(type)(FILE *fp, FalgprotoPacket *pkt)
#define FALGPROTO_MATCHER_NAME(type)        falgproto_##type##_matcher
#define FALGPROTO_MATCHER_DECL(type) \
    bool FALGPROTO_MATCHER_NAME(type) \
    (const char *big, size_t big_len, const char *little, size_t little_len)


unsigned                falgproto_get_count         (void);
int                     falgproto_get_protocol      (const char *name);
const char*             falgproto_get_name          (FalgprotoType protocol);
const char*             falgproto_get_description   (FalgprotoType protocol);
FalgprotoTransport      falgproto_get_transport     (FalgprotoType protocol);
FalgprotoParamGetter    falgproto_get_param_getter  (FalgprotoType protocol);
FalgprotoPrinter        falgproto_get_printer       (FalgprotoType protocol);
FalgprotoMatcher        falgproto_get_matcher       (FalgprotoType protocol);


#endif /* FALGPROTO_H */
