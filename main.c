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

#include "http_download.h"

int http_dl_log_level = 5;

/* Internal variables used by the timer.  */
static long http_dl_internal_secs, http_dl_internal_msecs;
static char *http_dl_agent_string = "Mozilla/5.0 (Windows NT 6.1; WOW64) " \
                                    "AppleWebKit/537.36 (KHTML, like Gecko) " \
                                    "Chrome/35.0.1916.153 Safari/537.36";

/* Count the digits in a (long) integer.  */
static int http_dl_numdigit(long a)
{
    int res = 1;

    while ((a /= 10) != 0) {
        ++res;
    }

    return res;
}

/* Create an internet connection to HOSTNAME on PORT.  The created
   socket will be stored to *SOCK.  */
http_dl_err_t http_dl_connect(int *sock, char *hostname, unsigned short port)
{
    int ret;
    struct sockaddr_in sock_name;
    /* struct hostent *hptr; */

    bzero(&sock_name, sizeof(sock_name));
    ret = inet_pton(AF_INET, hostname, &sock_name.sin_addr);
    if (ret != 1) {
        return HOSTERR;
    }

    /* Set port and protocol */
    sock_name.sin_family = AF_INET;
    sock_name.sin_port = htons(port);

    /* Make an internet socket, stream type.  */
    if ((*sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        return CONSOCKERR;
    }

    /* Connect the socket to the remote host.  */
    if (connect(*sock, (struct sockaddr *)&sock_name, sizeof(sock_name))) {
        if (errno == ECONNREFUSED) {
            return CONREFUSED;
        } else {
            return CONERROR;
        }
    }

    http_dl_log_debug("Created socket fd %d.", *sock);

    return NOCONERROR;
}

static int http_dl_iwrite(int fd, char *buf, int len)
{
    int res = 0;

    /* `write' may write less than LEN bytes, thus the outward loop
    keeps trying it until all was written, or an error occurred.  The
    inner loop is reserved for the usual EINTR f*kage, and the
    innermost loop deals with the same during select().  */
    while (len > 0) {
        do {
            res = write(fd, buf, len);
        } while (res == -1 && errno == EINTR);
        if (res <= 0) {
            break;
        }
        buf += res;
        len -= res;
    }
    return res;
}

static void http_dl_init_rbuf(http_dl_rbuf_t *rbuf, int fd)
{
    rbuf->fd = fd;
    rbuf->buffer_pos = rbuf->buffer;
    rbuf->buffer_left = 0;
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

/* Read at most LEN bytes from FD, storing them to BUF.  This is
   virtually the same as read(), but takes care of EINTR braindamage
   and uses select() to timeout the stale connections (a connection is
   stale if more than OPT.TIMEOUT time is spent in select() or
   read()).  */
static int http_dl_iread(int fd, char *buf, int len)
{
    int res;

    do {
        res = read(fd, buf, len);
    } while (res == -1 && errno == EINTR);

    return res;
}

/* Like http_dl_rbuf_readc(), only don't move the buffer position.  */
static int http_dl_peek_rbuf(http_dl_rbuf_t *rbuf, char *store)
{
    int res;

    if (rbuf->buffer_left == 0) {
        rbuf->buffer_pos = rbuf->buffer;
        rbuf->buffer_left = 0;
        res = http_dl_iread(rbuf->fd, rbuf->buffer, sizeof(rbuf->buffer));
        if (res <= 0) {
            return res;
        }
        rbuf->buffer_left = res;
    }

    *store = *rbuf->buffer_pos;
    return 1;
}

/* Get a header from read-buffer RBUF and return it in *HDR.

   As defined in RFC2068 and elsewhere, a header can be folded into
   multiple lines if the continuation line begins with a space or
   horizontal TAB.  Also, this function will accept a header ending
   with just LF instead of CRLF.

   The header may be of arbitrary length; the function will allocate
   as much memory as necessary for it to fit.  It need not contain a
   `:', thus you can use it to retrieve, say, HTTP status line.

   The trailing CRLF or LF are stripped from the header, and it is
   zero-terminated.   #### Is this well-behaved?  */
static int http_dl_get_header(http_dl_rbuf_t *rbuf, char **hdr, http_dl_header_get_t flags)
{
    int i;
    int res;
    int bufsize = 128;
    char *p;

    p = (char *)malloc(bufsize);
    *hdr = p;
    if (p == NULL) {
        http_dl_log_debug("alloc %d failed", bufsize);
        return HG_ERROR;
    }
    bzero(p, bufsize);

    for (i = 0; 1; i++) {
        if (i > bufsize - 1) {
            p = (char *)http_dl_xrealloc(p, (bufsize <<= 1));
            *hdr = p;   /* 更新返回值 */
            if (p == NULL) {
                http_dl_log_debug("alloc %d failed", bufsize);
                return HG_ERROR;
            }
            bzero(p, bufsize);
        }
        res = http_dl_rbuf_readc(rbuf, p + i);
        if (res == 1) {
            if (p[i] == '\n') {
                if (!((flags & HG_NO_CONTINUATIONS)
                        || i == 0
                        || (i == 1 && p[0] == '\r'))) {
                    char next;
                    /* If the header is non-empty, we need to check if
                    it continues on to the other line.  We do that by
                    peeking at the next character.  */
                    res = http_dl_peek_rbuf(rbuf, &next);
                    if (res == 0) {
                        return HG_EOF;
                    } else if (res == -1) {
                        return HG_ERROR;
                    }
                    /*  If the next character is HT or SP, just continue.  */
                    if (next == '\t' || next == ' ')
                    continue;
                }

                /* The header ends.  */
                p[i] = '\0';
                /* Get rid of '\r'.  */
                if (i > 0 && p[i - 1] == '\r') {
                    p[i - 1] = '\0';
                }

                break;
            }
        } else if (res == 0) {
            return HG_EOF;
        } else {
            return HG_ERROR;
        }
    }

    http_dl_log_debug("%s", p);

    return HG_OK;
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

    /* The standard format of HTTP-Version is: `HTTP/X.Y', where X is
     major version, and Y is minor version.  */
    if (strncmp(line, "HTTP/", 5) != 0) {
        return -1;
    }
    line += 5;

    /* Calculate major HTTP version.  */
    p = line;
    for (mjr = 0; isdigit(*line); line++) {
        mjr = 10 * mjr + (*line - '0');
    }
    if (*line != '.' || p == line) {
        return -1;
    }
    ++line;

    /* Calculate minor HTTP version.  */
    p = line;
    for (mnr = 0; isdigit(*line); line++) {
        mnr = 10 * mnr + (*line - '0');
    }
    if (*line != ' ' || p == line) {
        return -1;
    }
    /* Wget will accept only 1.0 and higher HTTP-versions.  The value of
     minor version can be safely ignored.  */
    if (mjr < 1) {
        return -1;
    }
    ++line;

    /* Calculate status code.  */
    if (!(isdigit(*line) && isdigit(line[1]) && isdigit(line[2]))) {
        return -1;
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
            return -1;
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

/* Reset the internal timer.  */
static void http_dl_reset_time(void)
{
    struct timeval t;

    gettimeofday (&t, NULL);
    http_dl_internal_secs = t.tv_sec;
    http_dl_internal_msecs = t.tv_usec / 1000;
}

static long http_dl_elapsed_time(void)
{
    struct timeval t;
    long ret;

    gettimeofday(&t, NULL);
    ret = ((t.tv_sec - http_dl_internal_secs) * 1000 + (t.tv_usec / 1000 - http_dl_internal_msecs));

    return ret;
}

/* Flush RBUF's buffer to WHERE.  Flush MAXSIZE bytes at most.
   Returns the number of bytes actually copied.  If the buffer is
   empty, 0 is returned.  */
static int http_dl_flush_rbuf(http_dl_rbuf_t *rbuf, char *where, int maxsize)
{
    int howmuch;

    if (rbuf->buffer_left == 0 || maxsize < 0) {
        return 0;
    } else {
        howmuch = MINVAL(rbuf->buffer_left, maxsize);
        if (where) {
            memcpy(where, rbuf->buffer_pos, howmuch);
        }
        rbuf->buffer_left -= howmuch;
        rbuf->buffer_pos += howmuch;
        return howmuch;
    }
}

static void http_dl_sp_percentage(long bytes, long expected)
{
    int percentage = (int)(100.0 * bytes / expected);
    http_dl_print_raw(" [%3d%%]", percentage);
}

/* Show the dotted progress report of file loading.  Called with
   length and a flag to tell it whether to reset or not.  It keeps the
   offset information in static local variables.

   Return value: 1 or 0, designating whether any dots have been drawn.

   If the init argument is set, the routine will initialize.

   If the res is non-zero, res/line_bytes lines are skipped
   (meaning the appropriate number ok kilobytes), and the number of
   "dots" fitting on the first line are drawn as ','.  */
#define HTTP_DL_SP_DOTS_IN_LINE     48
#define HTTP_DL_SP_DOT_SPACING      16
#define HTTP_DL_SP_DOT_BYTES        (0x1 << 14)
static int http_dl_show_progress(long res, long expected, http_dl_spflag_t flags)
{
    static long line_bytes;
    static long offs;
    static int ndot, nrow = 0;
    int any_output = 0;
    int dots_in_line = HTTP_DL_SP_DOTS_IN_LINE;
    int dot_spacing = HTTP_DL_SP_DOT_SPACING;
    int dot_bytes = HTTP_DL_SP_DOT_BYTES;

    if (flags == SP_FINISH) {
        if (expected) {
            int dot = ndot;
            char tmpstr[2 * HTTP_DL_SP_DOTS_IN_LINE + 1];
            char *tmpp = tmpstr;
            bzero(tmpstr, sizeof(tmpstr));
            for (; dot < dots_in_line; dot++) {
                if (!(dot % dot_spacing)) {
                    *tmpp++ = ' ';
                }
                *tmpp++ = ' ';
            }
            *tmpp = '\0';
            http_dl_print_raw("%s", tmpstr);
            http_dl_sp_percentage(nrow * line_bytes + ndot * dot_bytes + offs, expected);
        }
        http_dl_print_raw("\n\n");
        return 0;
    }

    /* Temporarily disable flushing.  */
    /* init set means initialization.  If res is set, it also means that
    the retrieval is *not* done from the beginning.  The part that
    was already retrieved is not shown again.  */
    if (flags == SP_INIT) {
        /* Generic initialization of static variables.  */
        offs = 0L;
        ndot = 0;
        nrow = 0;
        line_bytes = (long)dots_in_line * dot_bytes;
        if (res) {
            if (res >= line_bytes) {
                nrow = res / line_bytes;
                res %= line_bytes;
                http_dl_print_raw("\n          [ skipping %dK ]", (int) ((nrow * line_bytes) >> 10));
                ndot = 0;
            }
        }
        http_dl_print_raw("\n%5ldK ->", (nrow * line_bytes) >> 10);
    }

    /* Offset gets incremented by current value.  */
    offs += res;

    /*
     * While offset is >= opt.dot_bytes, print dots, taking care to
     * precede every 50th dot with a status message.
     */
    for ( ; offs >= dot_bytes; offs -= dot_bytes) {
        if (!(ndot % dot_spacing)) {
            http_dl_print_raw(" ");
        }
        any_output = 1;
        http_dl_print_raw("%s", flags == SP_INIT ? "," : ".");
        ++ndot;
        if (ndot == dots_in_line) {
            ndot = 0;
            ++nrow;
            if (expected) {
                http_dl_sp_percentage(nrow * line_bytes, expected);
            }
            http_dl_print_raw("\n%5ldK ->", (nrow * line_bytes) >> 10);
        }
    }

    /* Reenable flushing.  */
    if (any_output) {
        (void)0;
    }

    return any_output;
}

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

int main(int argc, char *argv[])
{
    int ret, avrspd;
    http_dl_urlinfo_t ui;
    http_dl_stat_t hs;
    int dt = 0;
    char host[HTTP_DL_HOST_LEN], local[HTTP_DL_LOCAL_LEN], path[HTTP_DL_PATH_LEN];
    char *p, *q;

    if (argc != 2 && argc != 3) {
        http_dl_print_raw("Usage: %s URL [Referer]\n", argv[0]);
        return -1;
    }

    bzero(&ui, sizeof(ui));
    bzero(&hs, sizeof(hs));
    bzero(host, HTTP_DL_HOST_LEN);
    bzero(local, HTTP_DL_LOCAL_LEN);
    bzero(path, HTTP_DL_PATH_LEN);

    /* 解析host */
    if (strstr(argv[1], HTTP_URL_PREFIX) != NULL) {
        q = argv[1] + HTTP_URL_PRE_LEN;
    } else {
        q = argv[1];
    }
    for (p = host; p < host + HTTP_DL_HOST_LEN - 1 && *q != '/' && *q != '\0'; p++, q++) {
        *p = *q;
    }
    if (p == host + HTTP_DL_HOST_LEN - 1) {
        http_dl_log_error("host length longer than %d", HTTP_DL_HOST_LEN - 1);
        return -1;
    }

    /* 解析path */
    for (p = path; p < path + HTTP_DL_PATH_LEN - 1; p++, q++) {
        if (*q == '\n' || *q == '\0' || *q == ' ') {
            break;
        } else {
            *p = *q;
        }
    }
    if (p == path + HTTP_DL_PATH_LEN - 1) {
        http_dl_log_error("path length longer than %d", HTTP_DL_PATH_LEN - 1);
        return -1;
    }

    /* 解析本地保存文件名 */
    q = argv[1] + strlen(argv[1]);
    for ( ; *q != '/' && q > argv[1]; q--) {
        (void)0;
    }
    if (q <= argv[1]) {
        http_dl_log_error("invalid URL, get local file name failed");
        return -1;
    }
    for (p = local, q = q + 1; p < local + HTTP_DL_LOCAL_LEN -1; p++, q++) {
        if (*q == '\n' || *q == '\0' || *q == ' ') {
            break;
        } else {
            *p = *q;
        }
    }
    if (p == local + HTTP_DL_LOCAL_LEN - 1) {
        http_dl_log_error("local file name longer than %d", HTTP_DL_LOCAL_LEN - 1);
        return -1;
    }

    ui.url = argv[1];
    ui.host = host;
    ui.local = local;
    ui.path = path;
    ui.port = 80;
    if (argc == 3) {
        ui.referer = argv[2];
    }
    dt |= ACCEPTRANGES;

    ret = http_dl_get(&ui, &hs, &dt);

    http_dl_log_debug("gethttp return %d\n", ret);
    http_dl_log_debug("HS error: %s\n", hs.error);
    http_dl_log_debug("HS remote time: %s\n", hs.remote_time);
    http_dl_log_debug("HS status code: %d\n", hs.statcode);
    http_dl_log_debug("HS delta time: %ld\n", hs.dltime);
    http_dl_log_debug("HS content length: %ld, (receive %ld)\n", hs.contlen, hs.len);

    http_dl_free(hs.remote_time);

    if (ret != RETRFINISHED) {
        http_dl_log_error("http_dl_get file failed, %d", ret);
        return -1;
    }

    if (hs.dltime != 0) {
        avrspd = hs.len / hs.dltime;
    } else {
        avrspd = 0;
    }
    http_dl_log_info("Content %ld KB, receive %ld KB, time %ld sec, average speed %d KB/s",
                        (hs.contlen >> 10),
                        (hs.len >> 10),
                        (hs.dltime / 1000),
                        avrspd);

    return 0;
}

