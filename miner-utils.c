#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <curl/curl.h>

struct data_buffer {
    void		*buf;
    size_t		len;
};

struct upload_buffer {
    const void	*buf;
    size_t		len;
};

static void databuf_free(struct data_buffer *db)
{
    if (!db)
        return;

    free(db->buf);

    memset(db, 0, sizeof(*db));
}

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb,
        void *user_data)
{
    struct data_buffer *db = user_data;
    size_t len = size * nmemb;
    size_t oldlen, newlen;
    void *newmem;
    static const unsigned char zero;

    oldlen = db->len;
    newlen = oldlen + len;

    newmem = realloc(db->buf, newlen + 1);
    if (!newmem)
        return 0;

    db->buf = newmem;
    db->len = newlen;
    memcpy((char*)db->buf + oldlen, ptr, len);
    memcpy((char*)db->buf + newlen, &zero, 1);	/* null terminate */

    return len;
}

static size_t upload_data_cb(void *ptr, size_t size, size_t nmemb,
        void *user_data)
{
    struct upload_buffer *ub = user_data;
    int len = size * nmemb;

    if (len > (int)ub->len)
        len = ub->len;

    if (len) {
        memcpy(ptr, ub->buf, len);
        ub->buf = (char*)(ub->buf) + len;
        ub->len -= len;
    }

    return len;
}

json_t *json_rpc_call(const char *url, const char *userpass, const char *rpc_req)
{
    CURL *curl;
    json_t *val;
    int rc;
    struct data_buffer all_data = { .buf = NULL, .len = 0 };
    struct upload_buffer upload_data;
    json_error_t err;
    struct curl_slist *headers = NULL;
    char len_hdr[64];

    curl = curl_easy_init();
    if (!curl)
        return NULL;

    if (0)
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, upload_data_cb);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60 /*sec*/);
    if (userpass) {
        curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    }
    curl_easy_setopt(curl, CURLOPT_POST, 1);

    if (0)
        printf("JSON protocol request:\n%s\n", rpc_req);

    upload_data.buf = rpc_req;
    upload_data.len = strlen(rpc_req);
    sprintf(len_hdr, "Content-Length: %lu",
            (unsigned long) upload_data.len);

    headers = curl_slist_append(headers,
            "Content-type: application/json");
    headers = curl_slist_append(headers, len_hdr);
    headers = curl_slist_append(headers, "Expect:"); /* disable Expect hdr*/

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    rc = curl_easy_perform(curl);
    if (rc)
        goto err_out;

    val = json_loads(all_data.buf, &err);
    if (!val) {
        fprintf(stderr, "JSON failed(%d): %s\n", err.line, err.text);
        goto err_out;
    }

    if (0) {
        char *s = json_dumps(val, JSON_INDENT(3));
        printf("JSON protocol response:\n%s\n", s);
        free(s);
    }

    databuf_free(&all_data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return val;

err_out:
    databuf_free(&all_data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return NULL;
}

char *bin2hex(unsigned char *p, size_t len)
{
    unsigned i;
    char *s = malloc((len * 2) + 1);
    if (!s)
        return NULL;

    for (i = 0; i < len; i++)
        sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);

    return s;
}

int hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
    while (*hexstr && len) {
        char hex_byte[3];
        unsigned int v;

        if (!hexstr[1]) {
            fprintf(stderr, "hex2bin str truncated\n");
            return 0;
        }

        hex_byte[0] = hexstr[0];
        hex_byte[1] = hexstr[1];
        hex_byte[2] = 0;

        if (sscanf(hex_byte, "%x", &v) != 1) {
            fprintf(stderr, "hex2bin sscanf '%s' failed\n",
                    hex_byte);
            return 0;
        }

        *p = (unsigned char) v;

        p++;
        hexstr += 2;
        len--;
    }

    return (len == 0 && *hexstr == 0) ? 1 : 0;
}
