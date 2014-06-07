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

typedef struct falgproto_param {
    char*   param;
    size_t  len;
    bool    dup;
    int     result;
} FalgprotoParam;

#define FALGPROTO_PARAM_RESULT_ERROR       -1
#define FALGPROTO_PARAM_RESULT_OK           0
#define FALGPROTO_PARAM_RESULT_NOT_FOUND    1
#define FALGPROTO_PARAM_RESULT_INCOMPLETE   2

typedef FalgprotoParam (*FalgprotoParamGetter) (const char *pkt);
typedef void           (*FalgprotoPrinter)     (const char *pkt, FILE *fp);


unsigned                falgproto_get_count         (void);
int                     falgproto_get_protocol      (const char *name);
const char*             falgproto_get_name          (FalgprotoType protocol);
const char*             falgproto_get_description   (FalgprotoType protocol);
FalgprotoTransport      falgproto_get_transport     (FalgprotoType protocol);
FalgprotoParamGetter    falgproto_get_param_getter  (FalgprotoType protocol);
FalgprotoPrinter        falgproto_get_printer       (FalgprotoType protocol);


#endif /* FALGPROTO_H */
