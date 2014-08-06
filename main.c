#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <alloca.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "http_download.h"

int http_dl_log_level = 6;

static char *http_dl_agent_string = "Mozilla/5.0 (Windows NT 6.1; WOW64) " \
                                    "AppleWebKit/537.36 (KHTML, like Gecko) " \
                                    "Chrome/35.0.1916.153 Safari/537.36";
static char *http_dl_agent_string_genuine = "Wget/1.5.3";
static http_dl_list_t http_dl_list_initial;
static http_dl_list_t http_dl_list_downloading;
static http_dl_list_t http_dl_list_finished;

/* Count the digits in a (long) integer.  */
static int http_dl_numdigit(long a)
{
    int res = 1;

    while ((a /= 10) != 0) {
        ++res;
    }

    return res;
}

static int http_dl_conn(char *hostname, unsigned short port)
{
    int ret;
    struct sockaddr_in sa;

    if (hostname == NULL) {
        return -HTTP_DL_ERR_INVALID;
    }

    bzero(&sa, sizeof(sa));
    ret = inet_pton(AF_INET, hostname, &sa.sin_addr);
    if (ret != 1) {
        return -HTTP_DL_ERR_INVALID;
    }

    /* Set port and protocol */
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    /* Make an internet socket, stream type.  */
    if ((ret = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        return -HTTP_DL_ERR_SOCK;
    }

    /* Connect the socket to the remote host.  */
    if (connect(ret, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(ret);
        return -HTTP_DL_ERR_CONN;
    }

    http_dl_log_debug("Created and connected socket fd %d.", ret);

    return ret;
}

static int http_dl_iwrite(int fd, char *buf, int len)
{
    int res = 0;

    if (buf == NULL || len <= 0) {
        return -HTTP_DL_ERR_INVALID;
    }

    /* 'write' may write less than LEN bytes, thus the outward loop
    keeps trying it until all was written, or an error occurred.  The
    inner loop is reserved for the usual EINTR f*kage, and the
    innermost loop deals with the same during select().  */
    while (len > 0) {
        do {
            res = write(fd, buf, len);
        } while (res == -1 && errno == EINTR);
        if (res <= 0) {
            return -HTTP_DL_ERR_WRITE;
        }
        buf += res;
        len -= res;
    }
    return len;
}

static void *http_dl_xrealloc(void *obj, size_t size)
{
    void *res;

    /* Not all Un*xes have the feature of realloc() that calling it with
    a NULL-pointer is the same as malloc(), but it is easy to
    simulate.  */
    if (obj) {
        res = realloc(obj, size);
    } else {
        res = malloc(size);
    }

    if (res == NULL) {
        http_dl_log_debug("allocate %d failed", size);
    }

    return res;
}

#if 0
/* Read at most LEN bytes from FD, storing them to BUF.  This is
   virtually the same as read(), but takes care of EINTR braindamage
   and uses select() to timeout the stale connections (a connection is
   stale if more than OPT.TIMEOUT time is spent in select() or
   read()).  */
static int http_dl_iread(int fd, char *buf, int len)
{
    int res;

    if (buf == NULL || len <= 0) {
        return -HTTP_DL_ERR_INVALID;
    }

    do {
        res = read(fd, buf, len);
    } while (res == -1 && errno == EINTR);

    if (res > 0) {
        return res;
    } else if (res == 0) {
        return -HTTP_DL_ERR_EOF;
    } else {
        return -HTTP_DL_ERR_READ;
    }
}

/* Parse the HTTP status line, which is of format:

   HTTP-Version SP Status-Code SP Reason-Phrase

   The function returns the status-code, or -1 if the status line is
   malformed.  The pointer to reason-phrase is returned in RP.  */
static int http_dl_parse_status_line(const char *line)
{
    /* (the variables must not be named `major' and `minor', because
     that breaks compilation with SunOS4 cc.)  */
    int mjr, mnr, statcode;
    const char *p;

    if (line == NULL) {
        return -HTTP_DL_ERR_INVALID;
    }

    /* The standard format of HTTP-Version is: `HTTP/X.Y', where X is
     major version, and Y is minor version.  */
    if (strncmp(line, "HTTP/", 5) != 0) {
        return -HTTP_DL_ERR_INVALID;
    }
    line += 5;

    /* Calculate major HTTP version.  */
    p = line;
    for (mjr = 0; isdigit(*line); line++) {
        mjr = 10 * mjr + (*line - '0');
    }
    if (*line != '.' || p == line) {
        return -HTTP_DL_ERR_INVALID;
    }
    ++line;

    /* Calculate minor HTTP version.  */
    p = line;
    for (mnr = 0; isdigit(*line); line++) {
        mnr = 10 * mnr + (*line - '0');
    }
    if (*line != ' ' || p == line) {
        return -HTTP_DL_ERR_INVALID;
    }
    /* Wget will accept only 1.0 and higher HTTP-versions.  The value of
     minor version can be safely ignored.  */
    if (mjr < 1) {
        return -HTTP_DL_ERR_INVALID;
    }
    ++line;

    /* Calculate status code.  */
    if (!(isdigit(*line) && isdigit(line[1]) && isdigit(line[2]))) {
        return -HTTP_DL_ERR_INVALID;
    }
    statcode = 100 * (*line - '0') + 10 * (line[1] - '0') + (line[2] - '0');

    /* Set up the reason phrase pointer.  */
    line += 3;
    /* RFC2068 requires SPC here, but we allow the string to finish
     here, in case no reason-phrase is present.  */
    if (*line != ' ') {
        if (*line != '\0') {
            http_dl_log_debug("reason: %s", line);
        } else {
            return -HTTP_DL_ERR_INVALID;
        }
    } else {
        http_dl_log_debug("Reason: %s", line + 1);
    }

    return statcode;
}

/* Skip LWS (linear white space), if present.  Returns number of
   characters to skip.  */
static int http_dl_clac_lws(const char *string)
{
    const char *p = string;

    if (string == NULL) {
        return -HTTP_DL_ERR_INVALID;
    }

    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        ++p;
    }

    return (p - string);
}

/* Check whether HEADER begins with NAME and, if yes, skip the `:' and
   the whitespace, and call PROCFUN with the arguments of HEADER's
   contents (after the ':' and space) and ARG.  Otherwise, return 0.  */
static int http_dl_header_process(const char *header,
                                  const char *name,
                                  int (*procfun)(const char *, void *),
                                  void *arg)
{
    int gap;

    /* Check whether HEADER matches NAME.  */
    while (*name && (tolower(*name) == tolower(*header))) {
        ++name, ++header;
    }

    if (*name || *header++ != ':') {
        return 0;
    }

    gap = http_dl_clac_lws(header);
    header += gap;

    return ((*procfun)(header, arg));
}

static int http_dl_header_extract_number (const char *header, void *closure)
{
    const char *p = header;
    long result;

    for (result = 0; isdigit(*p); p++) {
        result = 10 * result + (*p - '0');
    }
    if (*p != '\0') {
        return 0;
    }

    *(long *)closure = result;

    return 1;
}

/* Strdup HEADER, and place the pointer to CLOSURE. XXX 记得释放堆空间buffer */
static int http_dl_header_dup_str(const char *header, void *closure)
{
    int len;
    char *p = NULL;

    len = strlen(header) + 1;
    if (len == 1) {
        http_dl_log_debug("header string is NULL");
        return 0;
    }

    p = http_dl_xrealloc(p, len);
    if (p == NULL) {
        http_dl_log_debug("alloc failed");
        return 0;
    }
    bzero(p, len);
    strcpy(p, header);

    *(char **)closure = p;

    return 1;
}

/* Place 1 to ARG if the HDR contains the word "none", 0 otherwise.
   Used for `Accept-Ranges'.  */
static int http_dl_header_judge_none(const char *hdr, void *arg)
{
    int *where = (int *)arg;

    if (strstr(hdr, "none")) {
        *where = 1;
    } else {
        *where = 0;
    }

    return 1;
}

/* Parse the `Content-Range' header and extract the information it
   contains.  Returns 1 if successful, 0 otherwise.  */
static int http_dl_header_parse_range(const char *hdr, void *arg)
{
    http_dl_range_t *closure = (http_dl_range_t *)arg;
    long num;

    /* Certain versions of Nutscape proxy server send out
    `Content-Length' without "bytes" specifier, which is a breach of
    RFC2068 (as well as the HTTP/1.1 draft which was current at the
    time).  But hell, I must support it...  */
    if (strncasecmp(hdr, "bytes", 5) == 0) {
        hdr += 5;
        hdr += http_dl_clac_lws(hdr);
        if (!*hdr) {
            return 0;
        }
    }

    if (!isdigit(*hdr)) {
        return 0;
    }

    for (num = 0; isdigit(*hdr); hdr++) {
        num = 10 * num + (*hdr - '0');
    }

    if (*hdr != '-' || !isdigit(*(hdr + 1))) {
        return 0;
    }

    closure->first_byte_pos = num;
    ++hdr;

    for (num = 0; isdigit(*hdr); hdr++) {
        num = 10 * num + (*hdr - '0');
    }

    if (*hdr != '/' || !isdigit(*(hdr + 1))) {
        return 0;
    }

    closure->last_byte_pos = num;
    ++hdr;

    for (num = 0; isdigit(*hdr); hdr++) {
        num = 10 * num + (*hdr - '0');
    }

    closure->entity_length = num;
    return 1;
}
#endif

static void http_dl_reset_time(http_dl_info_t *di)
{
    if (di == NULL) {
        return;
    }

    gettimeofday(&di->start_time, NULL);
    di->elapsed_time = -1;  /* for unsigned long, -1 means maximum time */
}

/* unit is msecs */
static unsigned long http_dl_calc_elapsed(http_dl_info_t *di)
{
    struct timeval t;
    unsigned long ret;

    if (di == NULL) {
        return -1;
    }

    gettimeofday(&t, NULL);
    ret = (t.tv_sec - di->start_time.tv_sec) * 1000
           + (t.tv_usec - di->start_time.tv_usec) / 1000;
    di->elapsed_time = ret;

    return ret;
}

#if 0
/* Reads the contents of file descriptor FD, until it is closed, or a
   read error occurs.  The data is read in 8K chunks, and stored to
   stream fp, which should have been open for writing.  If BUF is
   non-NULL and its file descriptor is equal to FD, flush RBUF first.
   This function will *not* use the rbuf_* functions!

   The EXPECTED argument is passed to show_progress() unchanged, but
   otherwise ignored.

   If opt.verbose is set, the progress is also shown.  RESTVAL
   represents a value from which to start downloading (which will be
   shown accordingly).  If RESTVAL is non-zero, the stream should have
   been open for appending.

   The function exits and returns codes of 0, -1 and -2 if the
   connection was closed, there was a read error, or if it could not
   write to the output stream, respectively.

   IMPORTANT: The function flushes the contents of the buffer in
   rbuf_flush() before actually reading from fd.  If you wish to read
   from fd immediately, flush or discard the buffer.  */
static int http_dl_get_contents(int fd, FILE *fp, long *len, long restval,
                                long expected, http_dl_rbuf_t *rbuf)
{
    int res;
    static char c[8192];

    *len = restval;
    http_dl_show_progress(restval, expected, SP_INIT);
    if (rbuf && RBUF_FD(rbuf) == fd) {
        while ((res = http_dl_flush_rbuf (rbuf, c, sizeof (c))) != 0) {
            if (fwrite(c, sizeof(char), res, fp) < res) {
                return -2;
            }
            http_dl_show_progress(res, expected, SP_NONE);
            fflush(fp);
            *len += res;
        }
    }

    /* Read from fd while there is available data.  */
    do {
        res = http_dl_iread(fd, c, sizeof(c));
        if (res > 0) {
            if (fwrite(c, sizeof (char), res, fp) < res) {
                return -2;
            }
            http_dl_show_progress(res, expected, SP_NONE);
            fflush(fp);
            *len += res;
        }
    } while (res > 0);

    if (res < -1) {
        res = -1;
    }

    http_dl_show_progress (0, expected, SP_FINISH);

    return res;
}

static int http_dl_get(http_dl_urlinfo_t *u, http_dl_stat_t *hs, int *dt)
{
    char *request = NULL, *command, *path;
    char *pragma_h, *remhost;
    char *all_headers;
    char useragent[HTTP_DL_BUF_LEN], range[HTTP_DL_BUF_LEN], referer[HTTP_DL_URL_LEN];
    int lh, request_len;
    int sock, hcount, num_written, all_length, remport, statcode;
    long contlen, contrange;
    http_dl_err_t err;
    FILE *fp;
    http_dl_rbuf_t rbuf;
    char *hdr;

    /* Initialize certain elements of struct hstat.  */
    hs->len = 0L;
    hs->contlen = -1;
    hs->res = -1;
    hs->remote_time = NULL;
    hs->error = NULL;

    /* First: establish the connection.  */
    http_dl_log_info("Connecting to %s:%hu...", u->host, u->port);
    err = http_dl_connect(&sock, u->host, u->port);
    switch (err) {
    case HOSTERR:
        return HOSTERR;
        break;
    case CONSOCKERR:
        http_dl_log_debug("socket: %s", strerror(errno));
        return CONSOCKERR;
        break;
    case CONREFUSED:
        http_dl_log_debug("connect to %s:%hu refused.", u->host, u->port);
        close(sock);
        return CONREFUSED;
        break;
    case CONERROR:
        http_dl_log_debug("connect: %s", strerror(errno));
        close(sock);
        return CONERROR;
        break;
    case NOCONERROR:
        /* Everything is fine!  */
        http_dl_log_debug("connected!");
        break;
    default:
        http_dl_log_error("connect: unknown return %d", err);
        return -1;
        break;
    }

    path = u->path;
    command = "GET";

    bzero(referer, sizeof(referer));
    if (u->referer) {
        if (sizeof(referer) < strlen(u->referer) + 12) {
            http_dl_log_error("referer longer than %d: %s", sizeof(referer) - 12, u->referer);
            return -1;
        }
        sprintf(referer, "Referer: %s\r\n", u->referer);
    }

    if (*dt & SEND_NOCACHE) {
        pragma_h = "Pragma: no-cache\r\n";
    } else {
        pragma_h = "";
    }

    bzero(range, sizeof(range));
    if (hs->restval) {
        if (sizeof(range) < (http_dl_numdigit(hs->restval) + 17)) {
            http_dl_log_error("range string is longer than %d", sizeof(range) - 17);
            return -1;
        }
        /*
         * #### Gag me!  Some servers (e.g. WebSitePro) have been known
         * to misinterpret the following `Range' format, and return the
         * document as multipart/x-byte-ranges MIME type!
         * #### TODO: Interpret MIME types, recognize bullshits similar
         * the one described above, and deal with them!
         */
        sprintf(range, "Range: bytes=%ld-\r\n", hs->restval);
    }

    bzero(useragent, sizeof(useragent));
    if (*dt & GENUINE_AGENT) {
        sprintf(useragent, "Wget/1.5.3");
    } else {
        /* fake agent */
        if (sizeof(useragent) < strlen(http_dl_agent_string) + 1) {
            http_dl_log_error("User agent string longer than %d", sizeof(useragent) - 1);
            return -1;
        }
        sprintf(useragent, "%s", http_dl_agent_string);
    }

    remhost = u->host;
    remport = u->port;

    /* Allocate the memory for the request.  */
    request_len = strlen(command) + strlen(path)
                    + strlen(useragent)
                    + strlen(remhost) + http_dl_numdigit(remport)
                    + strlen(HTTP_ACCEPT)
                    + strlen(referer)
                    + strlen(range)
                    + strlen(pragma_h)
                    + 64;
    request = http_dl_xrealloc(request, request_len);
    if (request == NULL) {
        http_dl_log_error("allocate request buffer [%d] failed", request_len);
        return -1;
    }

    bzero(request, request_len);
    /* Construct the request.  */
    sprintf(request, "%s %s HTTP/1.0\r\n"
                     "User-Agent: %s\r\n"
                     "Host: %s:%d\r\n"
                     "Accept: %s\r\n"
                     "%s%s%s\r\n",
                      command, path,
                      useragent,
                      remhost, remport,
                      HTTP_ACCEPT,
                      referer, range, pragma_h);
    http_dl_log_debug("\n---request begin---\n%s---request end---\n", request);

    /* Send the request to server. */
    num_written = http_dl_iwrite(sock, request, strlen(request));
    if (num_written < 0) {
        http_dl_log_debug("failed writing HTTP request");
        http_dl_free(request);
        close(sock);
        return WRITEFAILED;
    }

    http_dl_free(request);

    http_dl_log_info("HTTP request sent, awaiting response...");
    contlen = contrange = -1;
    statcode = -1;
    *dt &= ~RETROKF;

    /* Before reading anything, initialize the rbuf.  */
    bzero(&rbuf, sizeof(rbuf));
    http_dl_init_rbuf(&rbuf, sock);

    all_headers = NULL;
    all_length = 0;
    /* Header-fetching loop.  */
    hcount = 0;
    while (1) {
        hdr = NULL;
        int status;

        ++hcount;
        /* Get the header.  */
        status = http_dl_get_header(&rbuf, &hdr,
                                /* Disallow continuations for status line.  */
                                (hcount == 1 ? HG_NO_CONTINUATIONS : HG_NONE));

        /* Check for errors.  */
        if (status == HG_EOF && *hdr) {
            /* This used to be an unconditional error, but that was
            somewhat controversial, because of a large number of
            broken CGI's that happily "forget" to send the second EOL
            before closing the connection of a HEAD request.

            So, the deal is to check whether the header is empty
            (*hdr is zero if it is); if yes, it means that the
            previous header was fully retrieved, and that -- most
            probably -- the request is complete.  "...be liberal in
            what you accept."  Oh boy.  */
            http_dl_log_debug("End of file while parsing headers.");
            http_dl_free(hdr);
            http_dl_free(all_headers);
            close(sock);
            return HEOF;
        } else if (status == HG_ERROR) {
            http_dl_log_debug("Read error (%s) in headers.",strerror(errno));
            http_dl_free(hdr);
            http_dl_free(all_headers);
            close(sock);
            return HERR;
        }

        /* If the headers are to be saved to a file later, save them to memory now.  */
        lh = strlen(hdr);
        all_headers = (char *)http_dl_xrealloc (all_headers, all_length + lh + 2);
        if (all_headers == NULL) {
            http_dl_log_debug("allocate all_headers buffer %d failed", all_length + lh + 2);
            http_dl_free(hdr);
            close(sock);
            return -1;
        }
        memcpy(all_headers + all_length, hdr, lh);
        all_length += lh;
        all_headers[all_length++] = '\n';
        all_headers[all_length] = '\0';

        /* Print the header if requested. */
        http_dl_log_debug("[%d] %s", hcount, hdr);

        /* Check for status line. */
        if (hcount == 1) {
            /* Parse the first line of server response.  */
            statcode = http_dl_parse_status_line(hdr);
            hs->statcode = statcode;
            /* Store the descriptive response.  */
            if (statcode == -1) { /* malformed response */
                /*
                 * A common reason for "malformed response" error is the
                 * case when no data was actually received.  Handle this
                 * special case.
                 */
                if (!*hdr) {
                    hs->error = "No data received";
                } else {
                    hs->error = "Malformed status line";
                }
                http_dl_free(hdr);
                break;
            } else {
                hs->error = "(no description)";
            }

            if (statcode != -1) {
                http_dl_log_info("HTTP response status code: %d", statcode);
            }

            goto done_header;
        }

        /* Exit on empty header.  */
        if (!*hdr) {
            http_dl_free(hdr);
            break;
        }

        /* Try getting content-length.  */
        if ((contlen == -1)
            && (http_dl_header_process(hdr, "Content-Length", http_dl_header_extract_number, &contlen))) {
            goto done_header;
        }

        /* Try getting last-modified.  */
        if ((!hs->remote_time)
            && (http_dl_header_process(hdr, "Last-Modified", http_dl_header_dup_str, &hs->remote_time))) {
            goto done_header;
        }

        /* Check for accept-ranges header.  If it contains the word 'none', disable the ranges. */
        if (*dt & ACCEPTRANGES) {
            int nonep;
            if (http_dl_header_process(hdr, "Accept-Ranges", http_dl_header_judge_none, &nonep)) {
                if (nonep) {
                    *dt &= ~ACCEPTRANGES;
                }
                goto done_header;
            }
        }

        /* Try getting content-range.  */
        if (contrange == -1) {
            http_dl_range_t closure;
            if (http_dl_header_process (hdr, "Content-Range", http_dl_header_parse_range, &closure)) {
                contrange = closure.first_byte_pos;
                goto done_header;
            }
        }

done_header:
        http_dl_free(hdr);
    }

    /* 20x responses are counted among successful by default.  */
    if (H_20X(statcode)) {
        http_dl_log_debug("status code %d (2xx), indicate success", statcode);
        *dt |= RETROKF;
    }

    if (contrange == -1) {
        hs->restval = 0;
    } else if (contrange != hs->restval
               || (H_PARTIAL(statcode) && contrange == -1)) {
        /* This means the whole request was somehow misunderstood by the server.  Bail out.  */
        http_dl_free(all_headers);
        close(sock);
        return RANGEERR;
    }

    if (hs->restval) {
        if (contlen != -1) {
            contlen += contrange;
        } else {
            contrange = -1; /* If conent-length was not sent, content-range will be ignored. */
        }
    }
    hs->contlen = contlen;

    /* Return if redirected.  */
    if (H_REDIRECTED(statcode) || statcode == HTTP_STATUS_MULTIPLE_CHOICES) {
        http_dl_log_info("WARNING: redirect request.");
    }

    /* Return if we have no intention of further downloading.  */
    if (!(*dt & RETROKF) || (*dt & HEAD_ONLY)) {
        /* In case someone cares to look...  */
        hs->len = 0L;
        hs->res = 0;
        http_dl_free(all_headers);
        close(sock);
        http_dl_log_debug("do not care body...");
        return RETRFINISHED;
    }

    fp = fopen(u->local, hs->restval ? "ab" : "wb");
    if (!fp) {
        http_dl_log_error("open %s: %s", u->local, strerror(errno));
        close(sock);
        http_dl_free(all_headers);
        return FOPENERR;
    }

    /*
     * #### This confuses the code that checks for file size.
     * There should be some overhead information.
     */
    http_dl_log_debug("ALL HEADERS:\n%s\n", all_headers);

    http_dl_reset_time();
    /* Get the contents of the document.  */
    hs->res = http_dl_get_contents(sock, fp, &hs->len, hs->restval,
                               (contlen != -1 ? contlen : 0),
                               &rbuf);
    hs->dltime = http_dl_elapsed_time();
    fclose(fp);
    http_dl_free(all_headers);
    close(sock);

    if (hs->res == -2) {
        return FWRITEERR;
    }

    return RETRFINISHED;
}
#endif

static http_dl_info_t *http_dl_create_info(char *url)
{
    http_dl_info_t *di;
    int url_len;
    char *p, *host, *path, *local;
    int host_len, path_len, local_len;
    int port = 0;

    if (url == NULL) {
        http_dl_log_debug("invalid input url");
        return NULL;
    }

    url_len = strlen(url);
    if (url_len >= HTTP_DL_URL_LEN) {
        http_dl_log_debug("url is longer than %d: %s", HTTP_DL_URL_LEN - 1, url);
        return NULL;
    }

    if ((p = strstr(url, HTTP_URL_PREFIX)) != NULL) {
        p = p + HTTP_URL_PRE_LEN;
    } else {
        p = url;
    }

    /* 解析host，以及可能存在的port */
    for (host = p, host_len = 0; *p != '/' && *p != ':' && *p != '\0'; p++, host_len++) {
        (void)0;
    }
    if (*p == ':') {
        p++;
        while (isdigit(*p)) {
            port = port * 10 + (*p - '0');
            if (port > 0xFFFF) {
                http_dl_log_debug("invalid port: %s", url);
                return NULL;
            }
            p++;
        }
        if (*p != '/') {
            http_dl_log_debug("invalid port: %s", url);
            return NULL;
        }
    } else if (*p == '\0') {
        http_dl_log_debug("invalid host: %s", host);
        return NULL;
    }
    if (host_len <= 0 || host_len >= HTTP_DL_HOST_LEN) {
        http_dl_log_debug("invalid host length: %s", host);
        return NULL;
    }

    /* 解析path */
    for (path = p, path_len = 0; *p != '\0' && *p != ' ' && *p != '\n'; p++, path_len++) {
        (void)0;
    }
    if (path_len <= 0 || path_len >= HTTP_DL_PATH_LEN) {
        http_dl_log_debug("invalid path length: %s", path);
        return NULL;
    }

    /* 解析本地保存文件名local */
    p--;
    for (local_len = 0; *p != '/'; p--, local_len++) {
        (void)0;
    }
    local = p + 1;
    if (local_len <= 0 || local_len >= HTTP_DL_LOCAL_LEN) {
        http_dl_log_debug("invalid local file name: %s", local);
        return NULL;
    }

    di = http_dl_xrealloc(NULL, sizeof(http_dl_info_t));
    if (di == NULL) {
        http_dl_log_debug("allocate failed");
        return NULL;
    }

    bzero(di, sizeof(http_dl_info_t));
    memcpy(di->url, url, url_len);
    memcpy(di->host, host, host_len);
    memcpy(di->path, path, path_len);
    memcpy(di->local, local, local_len);
    if (port != 0) {
        di->port = port;
    } else {
        di->port = 80;  /* 默认的http服务端口 */
    }

    di->stage = HTTP_DL_STAGE_INIT;
    INIT_LIST_HEAD(&di->list);

    di->recv_len = 0;
    di->content_len = 0;
    di->restart_len = 0;
    di->status_code = HTTP_DL_OK;
    di->sockfd = -1;
    di->filefd = -1;

    di->buf_data = di->buf;
    di->buf_tail = di->buf;

    return di;
}

static void http_dl_add_info_to_list(http_dl_info_t *info, http_dl_list_t *list)
{
    if (info == NULL || list == NULL) {
        return;
    }

    list_add_tail(&info->list, &list->list);
    list->count++;
}

static void http_dl_add_info_to_download_list(http_dl_info_t *info)
{
    if (info == NULL) {
        return;
    }

    http_dl_add_info_to_list(info, &http_dl_list_downloading);
    if (http_dl_list_downloading.maxfd < info->sockfd) {
        http_dl_list_downloading.maxfd = info->sockfd;
    }
}

static void http_dl_del_info_from_download_list(http_dl_info_t *info)
{
    if (info == NULL) {
        return;
    }

    list_del_init(&info->list);
    http_dl_list_downloading.count--;
    if (http_dl_list_downloading.count == 0) {
        http_dl_list_downloading.maxfd = -1;
    } else {
        /*
         * 注意: 此时应搜索downloading list，找出新的maxfd，但使用下面的方法，能快速找到一个
         *       不那么正确，但可用的值
         */
        if (http_dl_list_downloading.maxfd == info->sockfd) {
            http_dl_list_downloading.maxfd = info->sockfd - 1;
        }
    }
}

static void http_dl_init()
{
    http_dl_list_initial.count = 0;
    http_dl_list_initial.maxfd = -1;
    INIT_LIST_HEAD(&http_dl_list_initial.list);
    sprintf(http_dl_list_initial.name, "Initial list");

    http_dl_list_downloading.count = 0;
    http_dl_list_downloading.maxfd = -1;
    INIT_LIST_HEAD(&http_dl_list_downloading.list);
    sprintf(http_dl_list_downloading.name, "Downloading list");

    http_dl_list_finished.count = 0;
    http_dl_list_finished.maxfd = -1;
    INIT_LIST_HEAD(&http_dl_list_finished.list);
    sprintf(http_dl_list_finished.name, "Finished list");
}

static void http_dl_list_destroy(http_dl_list_t *list)
{
    http_dl_info_t *info, *next_info;

    if (list == NULL) {
        return;
    }

    list_for_each_entry_safe(info, next_info, &list->list, list, http_dl_info_t) {
        http_dl_log_debug("[%s] delete %s", list->name, info->url);
        list_del_init(&info->list);
        http_dl_free(info);
        list->count--;
    }

    if (list->count != 0) {
        http_dl_log_error("[%s] FATAL error, after destroy list->count %d (should 0).",
                                list->name, list->count);
    } else {
        http_dl_log_debug("[%s] destroy success.", list->name);
    }
}

static void http_dl_destroy()
{
    http_dl_list_destroy(&http_dl_list_initial);
    http_dl_list_destroy(&http_dl_list_downloading);
    http_dl_list_destroy(&http_dl_list_finished);
}

static void http_dl_list_debug(http_dl_list_t *list)
{
    http_dl_info_t *info;

    if (list == NULL) {
        return;
    }

    http_dl_print_raw("\n%s [%d]:\n", list->name, list->count);
    list_for_each_entry(info, &list->list, list, http_dl_info_t) {
        if (info->recv_len == 0) {
            http_dl_print_raw("\t%s\n", info->url);
        } else if (info->elapsed_time == -1) {
            http_dl_print_raw("\t%s [%ld KB]\n", info->local, info->recv_len >> 10);
        } else {
            http_dl_print_raw("\t%s [%ld KB] [%ld KB/s]\n",
                                info->local, info->recv_len >> 10, info->recv_len / info->elapsed_time);
        }
    }
    http_dl_print_raw("--------------\n");
}

static void http_dl_debug_show()
{
    http_dl_list_debug(&http_dl_list_initial);
    http_dl_list_debug(&http_dl_list_downloading);
    http_dl_list_debug(&http_dl_list_finished);
}

static int http_dl_send_req(http_dl_info_t *di)
{
    int ret, nwrite;
    char range[HTTP_DL_BUF_LEN], *useragent;
    char *request;
    int request_len;
    char *command = "GET";

    if (di == NULL) {
        return -HTTP_DL_ERR_INVALID;
    }

    if (di->stage < HTTP_DL_STAGE_SEND_REQUEST) {
        ret = http_dl_conn(di->host, di->port);
        if (ret < 0) {
            http_dl_log_debug("connect failed: %s:%d", di->host, di->port);
            return -HTTP_DL_ERR_CONN;
        }
        di->sockfd = ret;
        di->stage = HTTP_DL_STAGE_SEND_REQUEST;
    }

    bzero(range, sizeof(range));
    if (di->restart_len != 0) { /* 断点续传 */
        if (sizeof(range) < (http_dl_numdigit(di->restart_len) + 17)) {
            http_dl_log_error("range string is longer than %d", sizeof(range) - 17);
            return -HTTP_DL_ERR_INVALID;
        }
        sprintf(range, "Range: bytes=%ld-\r\n", di->restart_len);
    }

    if (di->flags & HTTP_DL_F_GENUINE_AGENT) {
        useragent = http_dl_agent_string_genuine;
    } else {
        useragent = http_dl_agent_string;
    }

    request_len = strlen(command) + strlen(di->path)
                + strlen(useragent)
                + strlen(di->host) + http_dl_numdigit(di->port)
                + strlen(HTTP_ACCEPT)
                + strlen(range)
                + 64;
    request = http_dl_xrealloc(NULL, request_len);
    if (request == NULL) {
        http_dl_log_error("allocate request buffer %d failed.", request_len);
        return -HTTP_DL_ERR_RESOURCE;
    }

    bzero(request, request_len);
    sprintf(request, "%s %s HTTP/1.0\r\n"
                     "User-Agent: %s\r\n"
                     "Host: %s:%d\r\n"
                     "Accept: %s\r\n"
                     "%s\r\n",
                     command, di->path,
                     useragent,
                     di->host, di->port,
                     HTTP_ACCEPT,
                     range);
    http_dl_log_debug("\n--- request begin ---\n%s--- request end ---\n", request);

    nwrite = http_dl_iwrite(di->sockfd, request, strlen(request));
    if (nwrite < 0) {
        http_dl_log_debug("write HTTP request failed.");
        ret = -HTTP_DL_ERR_WRITE;
        goto err_out;
    }

    http_dl_log_info("HTTP request sent, awaiting response...");
    http_dl_reset_time(di);
    ret = HTTP_DL_OK;

err_out:
    http_dl_free(request);

    return ret;
}

static void http_dl_list_proc_initial()
{
    http_dl_list_t *dl_list;
    http_dl_info_t *info, *next_info;
    int res;

    dl_list = &http_dl_list_initial;

    if (dl_list->count == 0) {
        return;
    }

    list_for_each_entry_safe(info, next_info, &dl_list->list, list, http_dl_info_t) {
        list_del_init(&info->list);
        dl_list->count--;
        res = http_dl_send_req(info);
        if (res == HTTP_DL_OK) {
            http_dl_add_info_to_download_list(info);
        } else {
            http_dl_log_debug("re-add %s to %s", info->url, dl_list->name);
            http_dl_add_info_to_list(info, dl_list);
        }
    }

    return;
}

static int http_dl_recv_resp(http_dl_info_t *info)
{
    int nread, free_space;

    if (info == NULL) {
        return -HTTP_DL_ERR_INVALID;
    }

    if (info->stage < HTTP_DL_STAGE_RECV_CONTENT) {
        info->stage = HTTP_DL_STAGE_RECV_CONTENT;
    }

    free_space = info->buf + HTTP_DL_READBUF_LEN - info->buf_tail;
    if (free_space < (HTTP_DL_READBUF_LEN >> 2)) {
        http_dl_log_debug("WARNING: info buffer free space %d too small", free_space);
    }

    nread = read(info->sockfd, info->buf_tail, free_space);
    if (nread == 0) {
        /* XXX: 下载结束，需要把info buffer里面的数据全部flush到文件中 */
        return -HTTP_DL_ERR_EOF;
    } else if (nread < 0) {
        http_dl_log_error("read failed, %d", nread);
        return -HTTP_DL_ERR_READ;
    }

    info->buf_tail += nread;
    info->recv_len += nread;

    /* XXX TODO: 从这里开始处理网络读数据 */
    info->buf_tail = info->buf;

    return HTTP_DL_OK;
}

static void http_dl_finish_req(http_dl_info_t *info)
{
    if (info == NULL) {
        return;
    }

    if (info->filefd >= 0) {
        http_dl_log_debug("close opened file fd %d", info->filefd);
        close(info->filefd);
        info->filefd = -1;
    }

    if (info->sockfd >= 0) {
        http_dl_log_debug("close opened socket fd %d", info->sockfd);
        close(info->sockfd);
        info->sockfd = -1;
    }

    http_dl_calc_elapsed(info);

    info->stage = HTTP_DL_STAGE_FINISH;
    http_dl_add_info_to_list(info, &http_dl_list_finished);
}

static int http_dl_list_proc_downloading()
{
    http_dl_list_t *dl_list;
    http_dl_info_t *info, *next_info;
    struct timeval tv;
    fd_set rset, rset_org;
    int res, read_res;

    dl_list = &http_dl_list_downloading;
    if (dl_list->count == 0) {
        return -HTTP_DL_ERR_INVALID;
    }

    FD_ZERO(&rset_org);
    list_for_each_entry(info, &dl_list->list, list, http_dl_info_t) {
        FD_SET(info->sockfd, &rset_org);
    }

    while (1) {
        if (dl_list->count == 0) {
            http_dl_log_info("All finished...");
            break;
        }

        bzero(&tv, sizeof(tv));
        tv.tv_sec = HTTP_DL_READ_TIMEOUT;
        tv.tv_usec = 0;

        FD_ZERO(&rset);
        memcpy(&rset, &rset_org, sizeof(fd_set));

        res = select(dl_list->maxfd + 1, &rset, NULL, NULL, &tv);
        if (res == 0) {
            /* 超时 */
            http_dl_log_debug("select timeout (%d secs)", HTTP_DL_READ_TIMEOUT);
            continue;
        } else if (res == -1 && errno == EINTR) {
            /* 被中断 */
            http_dl_log_debug("select interrupted by signal.");
            continue;
        } else if (res < 0){
            /* 出错 */
            http_dl_log_error("select failed, return %d", res);
            break;;
        }

        list_for_each_entry_safe(info, next_info, &dl_list->list, list, http_dl_info_t) {
            if (!FD_ISSET(info->sockfd, &rset)) {
                continue;
            }

            read_res = http_dl_recv_resp(info);
            if (read_res == -HTTP_DL_ERR_EOF) {
                /* 该次下载结束 */
                FD_CLR(info->sockfd, &rset_org);
                http_dl_del_info_from_download_list(info);
                http_dl_finish_req(info);
                continue;
            } else if (read_res == HTTP_DL_OK) {
                /* 该次下载正常接收数据，可以再次继续 */
                continue;
            } else {
                /* 下载，处理遇到问题 */
                http_dl_log_error("receive data from %s, sockfd %d failed.",
                                        info->url, info->sockfd);
                return -HTTP_DL_ERR_READ;
            }
        }
    }

    return HTTP_DL_OK;
}

static int http_dl_list_proc_finished()
{
    return HTTP_DL_OK;
}

int main(int argc, char *argv[])
{
    FILE *fp;
    char url_buf[HTTP_DL_URL_LEN];
    int url_len, ret = HTTP_DL_OK;
    http_dl_info_t *di;

    if (argc != 2) {
        http_dl_print_raw("Usage: %s <url_list.txt>\n", argv[0]);
        return -HTTP_DL_ERR_INVALID;
    }

    http_dl_init();

    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        http_dl_log_error("Open file %s failed", argv[1]);
        return -HTTP_DL_ERR_FOPEN;
    }

    while (1) {
        bzero(url_buf, sizeof(url_buf));
        if (fgets(url_buf, sizeof(url_buf), fp) == NULL) {
            break;
        }

        url_len = strlen(url_buf);
        if (url_buf[url_len - 1] != '\n') {
            http_dl_log_error("URL in file %s is too long", argv[1]);
            ret = -HTTP_DL_ERR_INVALID;
            goto err_out;
        }
        url_buf[url_len - 1] = '\0';

        di = http_dl_create_info(url_buf);
        if (di == NULL) {
            http_dl_log_info("Create download task %s failed.", url_buf);
            continue;
        }

        http_dl_add_info_to_list(di, &http_dl_list_initial);

        http_dl_log_info("Create download task %s success.", url_buf);
    }

    http_dl_debug_show();

    http_dl_list_proc_initial();

    http_dl_debug_show();

    http_dl_list_proc_downloading();

    http_dl_debug_show();

    http_dl_list_proc_finished();

    http_dl_debug_show();

err_out:
    http_dl_destroy();
    fclose(fp);

    return ret;
}
