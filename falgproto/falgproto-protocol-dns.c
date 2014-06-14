/* vim: set sw=4 ts=4 sts=4 et: */

#include "config.h"
#include "falgproto.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static inline int get_question_count (
    const char *pkt, size_t len, uint16_t *result) {

    if (len < 12) {
        return -1;
    }

    uint16_t result_ne;
    memcpy (&result_ne, pkt + 4, 2);
    *result = ntohs (result_ne);

    return 0;
}

/* XXX: We only inspect the first question in the packet, as we
 *      don't know which question should we use to decide the
 *      destination. */
static inline ssize_t get_question_name (
    const char *pkt_s, size_t len, char *out_s) {

    /* String length are always unsigned. */
    const unsigned char *pkt = (const unsigned char*)pkt_s;
    unsigned char *out = (unsigned char*)out_s;

    /* We assume get_question_count are called before this function, so
     * we don't get a malformed or truncated packet */
    ssize_t i = 12, j = 0, out_len = 0;
    bool in_pointer = false;
    for (; i < len && pkt[i] != 0; j++) {

        /* Handle DNS name pointers, but this should not happen because this
         * is the first name field in the entire packet */
        if (pkt[i] > 63) {

            /* DNS name pointer should not be nested */
            if (in_pointer) {
                return -1;
            }

            if (i + 1 >= len) {
                return -1;
            }

            uint16_t next_label;
            memcpy (&next_label, pkt + i, 2);

            in_pointer = true;
            i = ntohs (next_label) & ~(0xc000);
            if (i >= len) {
                return -1;
            }
        }

        unsigned int label_len = pkt[i];
        for (i++; i < len && label_len > 0; i++, j++, label_len--) {
            if (out != NULL) {
                out[j] = pkt[i];
            }
        }
        if (i >= len) {
            return -1;
        }
        if (out != NULL) {
            if (pkt[i] != 0) {
                out[j] = '.';
            } else {
                out[j] = '\0';
            }
        }

        out_len = j;
    }

    if (pkt[i] != 0) {
        return -1;
    }

    return out_len;
}

/* We only handle the first packet now, as it is not possible for the
 * the question to exceed the 512 bytes limit. */
FALGPROTO_PARAM_GETTER_DECL (dns) {

    char *payload = pkt->payload;
    size_t len = pkt->len;

    uint16_t question_count;
    if (get_question_count (payload, len, &question_count) < 0) {
        return (FalgprotoParam) { .result = FALGPROTO_PARAM_RESULT_BAD_FORMAT };
    }
    if (question_count == 0) {
        return (FalgprotoParam) { .result = FALGPROTO_PARAM_RESULT_NOT_FOUND };
    }

    ssize_t question_name_len = get_question_name (payload, len, NULL);
    if (question_name_len < 0) {
        return (FalgprotoParam) { .result = FALGPROTO_PARAM_RESULT_BAD_FORMAT };
    }

    char *question_name = malloc (question_name_len + 1);
    if (question_name == NULL) {
        return (FalgprotoParam) { .result = FALGPROTO_PARAM_RESULT_ERROR };
    }

    get_question_name (payload, len, question_name);
    return (FalgprotoParam) {
        .param   = question_name,
        .len     = question_name_len,
        .dup     = true,
        .result  = FALGPROTO_PARAM_RESULT_OK };
}

FALGPROTO_PRINTER_DECL (dns) {

    char *payload = pkt->payload;
    size_t len = pkt->len;

    uint16_t question_count;
    if (get_question_count (payload, len, &question_count) < 0) {
        fputs ("DNS: Cannot get question count\n", fp);
        return;
    }

    fprintf (fp, "DNS: Question count: %" PRIu16 "\n", question_count);
    if (question_count == 0) {
        fputs ("DNS: Why the question count is zero?\n", fp);
        return;
    }

    ssize_t question_name_len = get_question_name (payload, len, NULL);
    if (question_name_len < 0) {
        fputs ("DNS: Malformed question name\n", fp);
        return;
    }

    char question_name[question_name_len + 1];
    get_question_name (payload, len, question_name);
    fputs ("DNS: Question name: ", fp);
    fputs (question_name, fp);
    fputc ('\n', fp);
    fprintf (fp, "DNS: Question name length: %zd\n", question_name_len);
}
