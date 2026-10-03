#define _POSIX_C_SOURCE 200809L
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* BIO I/O uses the same synchronous, thread-owned deadlines as plaintext.
 * SSL never owns the socket; the PG connection closes it after freeing TLS.
 * A session must have one exclusive caller, as required by DB/pool ownership. */
extern int pg_socket_receive(int, unsigned char *, int);
extern int pg_socket_send(int, const unsigned char *, int);
extern int pg_deadline_expired(void);

typedef struct {
    int fd;
    char *host, *ca;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO_METHOD *method;
    char error[256];
} pg_tls;

static int bio_create(BIO *b) { BIO_set_init(b, 1); return 1; }
static int bio_destroy(BIO *b) { (void)b; return 1; }
static int bio_read(BIO *b, char *buf, int n) {
    pg_tls *s = BIO_get_data(b);
    BIO_clear_retry_flags(b);
    return pg_socket_receive(s->fd, (unsigned char *)buf, n);
}
static int bio_write(BIO *b, const char *buf, int n) {
    pg_tls *s = BIO_get_data(b);
    BIO_clear_retry_flags(b);
    return pg_socket_send(s->fd, (const unsigned char *)buf, n);
}
static long bio_ctrl(BIO *b, int cmd, long arg, void *ptr) {
    (void)b; (void)arg; (void)ptr;
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}
static int fail(pg_tls *s, const char *operation) {
    long verification = s->ssl ? SSL_get_verify_result(s->ssl) : X509_V_OK;
    unsigned long code = ERR_get_error();
    char detail[160] = "TLS operation failed";
    if (pg_deadline_expired()) snprintf(detail, sizeof(detail), "transport deadline expired");
    else if (verification != X509_V_OK)
        snprintf(detail, sizeof(detail), "%s", X509_verify_cert_error_string(verification));
    else if (code) ERR_error_string_n(code, detail, sizeof(detail));
    snprintf(s->error, sizeof(s->error), "%s: %s", operation, detail);
    return -1;
}

/* Only copies managed strings here. File/trust loading and TLS work happen in
 * the collect-safe handshake call, with no managed pointers retained. */
void *pg_tls_new(int fd, const char *host, const char *ca) {
    pg_tls *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->fd = fd;
    s->host = strdup(host);
    s->ca = strdup(ca);
    if (!s->host || !s->ca) { free(s->host); free(s->ca); free(s); return NULL; }
    return s;
}
void pg_tls_free(void *pointer) {
    pg_tls *s = pointer;
    if (!s) return;
    /* No blocking close_notify exchange during failure/cancellation cleanup. */
    SSL_free(s->ssl);
    SSL_CTX_free(s->ctx);
    BIO_meth_free(s->method);
    free(s->host); free(s->ca); free(s);
}
const char *pg_tls_error(void *pointer) { return ((pg_tls *)pointer)->error; }

int pg_tls_handshake(void *pointer) {
    pg_tls *s = pointer;
    ERR_clear_error();
    if (!s->host[0] || pg_deadline_expired()) return fail(s, "TLS configuration");
    s->ctx = SSL_CTX_new(TLS_client_method());
    if (!s->ctx) return fail(s, "TLS context");
    if (!SSL_CTX_set_min_proto_version(s->ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(s->ctx, TLS1_3_VERSION)) return fail(s, "TLS version");
    SSL_CTX_set_verify(s->ctx, SSL_VERIFY_PEER, NULL);
    /* Do not inherit a verification store from OpenSSL's system SSL config:
     * explicit CA selection must not silently acquire additional anchors. */
    X509_STORE *trust = X509_STORE_new();
    if (!trust) return fail(s, "TLS trust store");
    SSL_CTX_set_cert_store(s->ctx, trust);
    if (SSL_CTX_set1_verify_cert_store(s->ctx, trust) != 1 ||
        SSL_CTX_set_purpose(s->ctx, X509_PURPOSE_SSL_SERVER) != 1) return fail(s, "TLS verification policy");
    X509_VERIFY_PARAM_clear_flags(SSL_CTX_get0_param(s->ctx),
        X509_V_FLAG_NO_CHECK_TIME | X509_V_FLAG_USE_CHECK_TIME | X509_V_FLAG_PARTIAL_CHAIN);
    SSL_CTX_set_verify_depth(s->ctx, 8);
    SSL_CTX_set_max_cert_list(s->ctx, 262144);
    SSL_CTX_set_options(s->ctx, SSL_OP_NO_TICKET);
    if (s->ca[0]) {
        if (SSL_CTX_load_verify_locations(s->ctx, s->ca, NULL) != 1) return fail(s, "TLS CA file");
    } else if (SSL_CTX_set_default_verify_paths(s->ctx) != 1) return fail(s, "TLS system trust");
    s->ssl = SSL_new(s->ctx);
    if (!s->ssl) return fail(s, "TLS session");
    X509_VERIFY_PARAM *param = SSL_get0_param(s->ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS |
                                         X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    unsigned char ip[16];
    if (inet_pton(AF_INET, s->host, ip) == 1 || inet_pton(AF_INET6, s->host, ip) == 1) {
        if (X509_VERIFY_PARAM_set1_ip_asc(param, s->host) != 1) return fail(s, "TLS IP identity");
    } else {
        if (SSL_set1_host(s->ssl, s->host) != 1 ||
            SSL_set_tlsext_host_name(s->ssl, s->host) != 1) return fail(s, "TLS DNS identity");
    }
    s->method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "idris2-pg deadline socket");
    if (!s->method || !BIO_meth_set_create(s->method, bio_create) ||
        !BIO_meth_set_destroy(s->method, bio_destroy) ||
        !BIO_meth_set_read(s->method, bio_read) || !BIO_meth_set_write(s->method, bio_write) ||
        !BIO_meth_set_ctrl(s->method, bio_ctrl)) return fail(s, "TLS BIO methods");
    BIO *bio = BIO_new(s->method);
    if (!bio) return fail(s, "TLS BIO");
    BIO_set_data(bio, s);
    SSL_set_bio(s->ssl, bio, bio);
    if (SSL_connect(s->ssl) != 1 || pg_deadline_expired()) return fail(s, "TLS handshake");
    X509 *peer = SSL_get1_peer_certificate(s->ssl);
    if (!peer) return fail(s, "TLS missing peer certificate");
    X509_free(peer);
    if (SSL_get_verify_result(s->ssl) != X509_V_OK) return fail(s, "TLS peer verification");
    return 0;
}
int pg_tls_send(void *pointer, const unsigned char *bytes, int count) {
    pg_tls *s = pointer;
    ERR_clear_error();
    if (count <= 0 || pg_deadline_expired()) return fail(s, "TLS send");
    int n = SSL_write(s->ssl, bytes, count);
    if (n <= 0 || pg_deadline_expired()) return fail(s, "TLS send");
    return n;
}
int pg_tls_receive(void *pointer, unsigned char *bytes, int count) {
    pg_tls *s = pointer;
    ERR_clear_error();
    if (count <= 0 || pg_deadline_expired()) return fail(s, "TLS receive");
    int n = SSL_read(s->ssl, bytes, count);
    if (n <= 0 || pg_deadline_expired()) return fail(s, "TLS receive");
    return n;
}
