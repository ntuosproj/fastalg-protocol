/* vim: set sw=4 ts=4 sts=4 et: */

#include "config.h"
#include "falgproto.h"

#include <stddef.h>
#include <strings.h>


struct proto_info {
    FalgprotoType           protocol;
    FalgprotoTransport      transport;
    char*                   name;
    char*                   description;
    FalgprotoParamGetter    param_getter;
    FalgprotoPrinter        printer;
    FalgprotoMatcher        matcher;
};

/* protocol implementation declaraion */
FALGPROTO_PARAM_GETTER_DECL (dns);
FALGPROTO_PRINTER_DECL (dns);

/* matcher implementation declaraion */
FALGPROTO_MATCHER_DECL (hostname);

static struct proto_info info[] = {
    { FALGPROTO_TYPE_HTTP,      FALGPROTO_TRANSPORT_TCP,  "http",
      "HTTP",
      NULL,
      NULL,
      NULL },
    { FALGPROTO_TYPE_HTTPS,     FALGPROTO_TRANSPORT_TCP,  "https",
      "HTTPS",
      NULL,
      NULL,
      NULL },
    { FALGPROTO_TYPE_DNS,       FALGPROTO_TRANSPORT_UDP,  "dns",
      "DNS",
      FALGPROTO_PARAM_GETTER_NAME (dns),
      FALGPROTO_PRINTER_NAME (dns),
      FALGPROTO_MATCHER_NAME (hostname) },
    { FALGPROTO_TYPE_FTP,       FALGPROTO_TRANSPORT_TCP,  "ftp",
      "FTP",
      NULL,
      NULL,
      NULL },
    { FALGPROTO_TYPE_SSH,       FALGPROTO_TRANSPORT_TCP,  "ssh",
      "SSH",
      NULL,
      NULL,
      NULL },
    { FALGPROTO_TYPE_LDAP,      FALGPROTO_TRANSPORT_TCP,  "ldap",
      "LDAP",
      NULL,
      NULL,
      NULL },
    { FALGPROTO_TYPE_MAX,       0, NULL, NULL, NULL, NULL, NULL }
};

unsigned falgproto_get_count (void) {
    return FALGPROTO_TYPE_MAX;
}

int falgproto_get_protocol (const char *name) {
    for (size_t i = 0; info[i].name != NULL; i++) {
        if (strcasecmp (name, info[i].name) == 0) {
            return info[i].protocol;
        }
    }
    return -1;
}

const char* falgproto_get_name (FalgprotoType protocol) {
    return info[protocol].name;
}

const char* falgproto_get_description (FalgprotoType protocol) {
    return info[protocol].description;
}

FalgprotoTransport falgproto_get_transport (FalgprotoType protocol) {
    return info[protocol].transport;
}

FalgprotoParamGetter falgproto_get_param_getter (FalgprotoType protocol) {
    return info[protocol].param_getter;
}

FalgprotoPrinter falgproto_get_printer (FalgprotoType protocol) {
    return info[protocol].printer;
}

FalgprotoMatcher falgproto_get_matcher (FalgprotoType protocol) {
    return info[protocol].matcher;
}
