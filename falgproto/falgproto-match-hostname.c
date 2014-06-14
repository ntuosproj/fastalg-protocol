/* vim: set sw=4 ts=4 sts=4 et: */

#include "config.h"
#include "falgproto.h"

#include <ctype.h>
#include <stdbool.h>


FALGPROTO_MATCHER_DECL (hostname) {

    const char *big_end = big + big_len;
    const char *little_end = little + little_len;

    for (; big_end >= big && little_end >= little &&
           toupper (*big_end) == toupper (*little_end);
           big_end--, little_end--);

    if (little_end < little) {
        if (big_end >= big) {
            if (*big_end == '.') {
                return true;
            } else {
                return false;
            }
        } else {
            return true;
        }
    }

    return false;
}
