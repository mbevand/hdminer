extern json_t *json_rpc_call(const char *url, const char *userpass,
        const char *rpc_req);
extern char *bin2hex(unsigned char *p, size_t len);
extern bool hex2bin(unsigned char *p, const char *hexstr, size_t len);
