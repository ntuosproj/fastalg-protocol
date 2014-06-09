/* vim: set sw=4 ts=4 sts=4 et: */

#include "config.h"
#include "falgproto.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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
    ssize_t i = 12, j = 0;
    for (; i < len && pkt[i] != 0; j++) {
        unsigned int label_len = pkt[i];
        for (i++; i < len && label_len > 0; i++, j++, label_len--) {
            if (out != NULL) {
                out[j] = pkt[i];
            }
        }
        if (out != NULL) {
            if (pkt[i] != 0) {
                out[j] = '.';
            } else {
                out[j] = '\0';
            }
        }
    }

    if (pkt[i] != 0) {
        printf ("%hhu %c\n", pkt[i], pkt[i]);
        return -1;
    }

    return i - 12 - 1;
}

FALGPROTO_PARAM_GETTER_DECL (dns) {

    uint16_t question_count;
    if (get_question_count (pkt, len, &question_count) < 0) {
        return (FalgprotoParam) { .result = FALGPROTO_PARAM_RESULT_TRUNCATED };
    }
    if (question_count == 0) {
        return (FalgprotoParam) { .result = FALGPROTO_PARAM_RESULT_NOT_FOUND };
    }

    ssize_t question_name_len = get_question_name (pkt, len, NULL);
    if (question_name_len < 0) {
        return (FalgprotoParam) { .result = FALGPROTO_PARAM_RESULT_TRUNCATED };
    }

    char *question_name = malloc (question_name_len + 1);
    if (question_name == NULL) {
        return (FalgprotoParam) { .result = FALGPROTO_PARAM_RESULT_ERROR };
    }

    get_question_name (pkt, len, question_name);
    return (FalgprotoParam) {
        .param   = question_name,
        .len     = question_name_len,
        .dup     = true,
        .result  = FALGPROTO_PARAM_RESULT_OK };
}

FALGPROTO_PRINTER_DECL (dns) {

    uint16_t question_count;
    if (get_question_count (pkt, len, &question_count) < 0) {
        fputs ("DNS: Cannot get question count\n", fp);
        return;
    }

    fprintf (fp, "DNS: Question count: %" PRIu16 "\n", question_count);
    if (question_count == 0) {
        fputs ("DNS: Why the question count is zero?\n", fp);
        return;
    }

    ssize_t question_name_len = get_question_name (pkt, len, NULL);
    if (question_name_len < 0) {
        fputs ("DNS: Malformed question name\n", fp);
        return;
    }

    char question_name[question_name_len + 1];
    get_question_name (pkt, len, question_name);
    fputs ("DNS: Question name: ", fp);
    fputs (question_name, fp);
    fputc ('\n', fp);
    fprintf (fp, "DNS: Question name length: %zd\n", question_name_len);
}
