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

/* Document-type flags */
enum
{
  TEXTHTML      = 0x0001,	/* document is of type text/html */
  RETROKF       = 0x0002,	/* retrieval was OK */
  HEAD_ONLY     = 0x0004,	/* only send the HEAD request */
  SEND_NOCACHE  = 0x0008,	/* send Pragma: no-cache directive */
  ACCEPTRANGES  = 0x0010	/* Accept-ranges header was found */
};

/* Universal error type -- used almost everywhere.
   This is, of course, utter crock.  */
typedef enum
{
  NOCONERROR, HOSTERR, CONSOCKERR, CONERROR,
  CONREFUSED, NEWLOCATION, NOTENOUGHMEM, CONPORTERR,
  BINDERR, BINDOK, LISTENERR, ACCEPTERR, ACCEPTOK,
  CONCLOSED, FTPOK, FTPLOGINC, FTPLOGREFUSED, FTPPORTERR,
  FTPNSFOD, FTPRETROK, FTPUNKNOWNTYPE, FTPRERR,
  FTPREXC, FTPSRVERR, FTPRETRINT, FTPRESTFAIL,
  URLOK, URLHTTP, URLFTP, URLFILE, URLUNKNOWN, URLBADPORT,
  URLBADHOST, FOPENERR, FWRITEERR, HOK, HLEXC, HEOF,
  HERR, RETROK, RECLEVELEXC, FTPACCDENIED, WRONGCODE,
  FTPINVPASV, FTPNOPASV,
  RETRFINISHED, READERR, TRYLIMEXC, URLBADPATTERN,
  FILEBADFILE, RANGEERR, RETRBADPATTERN, RETNOTSUP,
  ROBOTSOK, NOROBOTS, PROXERR, AUTHFAILED, QUOTEXC, WRITEFAILED
} uerr_t;

enum {
  HG_OK, HG_ERROR, HG_EOF
};

enum header_get_flags { HG_NONE = 0,
			HG_NO_CONTINUATIONS = 0x2 };


/* Retrieval stream */
struct rbuf
{
  int fd;
  char buffer[4096];		/* the input buffer */
  char *buffer_pos;		/* current position in the buffer */
  size_t buffer_left;		/* number of bytes left in the buffer:
				   buffer_left = buffer_end - buffer_pos */
  int internal_dont_touch_this;	/* used by RBUF_READCHAR macro */
};

/* Structure containing info on a URL.  */
struct urlinfo
{
  char *url;			/* Unchanged URL */
  char *host;			/* Extracted hostname */
  unsigned short port;
  char *path;	/* Path, as well as dir and file
				   (properly decoded) */
  char *referer;		/* The source from which the request
				   URI was obtained */
  char *local;			/* The local filename of the URL
				   document */
};

struct http_stat
{
  long len;			/* received length */
  long contlen;			/* expected length */
  long restval;			/* the restart value */
  int res;			/* the result of last read */
  char *remote_time;		/* remote time-stamp string */
  char *error;			/* textual HTTP error */
  int statcode;			/* status code */
  long dltime;			/* time of the download */
};

struct http_process_range_closure {
  long first_byte_pos;
  long last_byte_pos;
  long entity_length;
};


#define HTTP_ACCEPT "*/*"
char *version_string = "1.5.3";
/* Internal variables used by the timer.  */
static long internal_secs, internal_msecs;


/* Count the digits in a (long) integer.  */
int numdigit (long a)
{
  int res = 1;
  while ((a /= 10) != 0)
    ++res;
  return res;
}

/* Create an internet connection to HOSTNAME on PORT.  The created
   socket will be stored to *SOCK.  */
uerr_t make_connection (int *sock, char *hostname, unsigned short port)
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
  sock_name.sin_port = htons (port);

  /* Make an internet socket, stream type.  */
  if ((*sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    return CONSOCKERR;

  /* Connect the socket to the remote host.  */
  if (connect(*sock, (struct sockaddr *) &sock_name, sizeof (sock_name)))
    {
      if (errno == ECONNREFUSED)
	return CONREFUSED;
      else
	return CONERROR;
    }
  printf("Created fd %d.\n", *sock);
  return NOCONERROR;
}

int iwrite (int fd, char *buf, int len)
{
  int res = 0;

  /* `write' may write less than LEN bytes, thus the outward loop
     keeps trying it until all was written, or an error occurred.  The
     inner loop is reserved for the usual EINTR f*kage, and the
     innermost loop deals with the same during select().  */
  while (len > 0)
    {
      do
	{
	  res = write(fd, buf, len);
	}
      while (res == -1 && errno == EINTR);
      if (res <= 0)
	break;
      buf += res;
      len -= res;
    }
  return res;
}

void rbuf_initialize (struct rbuf *rbuf, int fd)
{
  rbuf->fd = fd;
  rbuf->buffer_pos = rbuf->buffer;
  rbuf->buffer_left = 0;
}

void *xrealloc (void *obj, size_t size)
{
  void *res;

  /* Not all Un*xes have the feature of realloc() that calling it with
     a NULL-pointer is the same as malloc(), but it is easy to
     simulate.  */
  if (obj)
    res = realloc(obj, size);
  else
    res = malloc(size);
  if (!res) {
    printf("xrealloc failed\n");
    exit(-1);
  }
  return res;
}

/* Read at most LEN bytes from FD, storing them to BUF.  This is
   virtually the same as read(), but takes care of EINTR braindamage
   and uses select() to timeout the stale connections (a connection is
   stale if more than OPT.TIMEOUT time is spent in select() or
   read()).  */
int iread (int fd, char *buf, int len)
{
  int res;

  do
    {
      res = read(fd, buf, len);
    }
  while (res == -1 && errno == EINTR);

  return res;
}

#define RBUF_READCHAR(rbuf, store)					\
((rbuf)->buffer_left							\
 ? (--(rbuf)->buffer_left,						\
    *((char *) (store)) = *(rbuf)->buffer_pos++, 1)			\
 : ((rbuf)->buffer_pos = (rbuf)->buffer,				\
    ((((rbuf)->internal_dont_touch_this					\
       = iread ((rbuf)->fd, (rbuf)->buffer,				\
		sizeof ((rbuf)->buffer))) <= 0)				\
     ? (rbuf)->internal_dont_touch_this					\
     : ((rbuf)->buffer_left = (rbuf)->internal_dont_touch_this - 1,	\
	*((char *) (store)) = *(rbuf)->buffer_pos++,			\
	1))))

#define FREE_MAYBE(foo) do { if (foo) free(foo); } while (0)

/* Like rbuf_readchar(), only don't move the buffer position.  */
int rbuf_peek (struct rbuf *rbuf, char *store)
{
  if (!rbuf->buffer_left)
    {
      int res;
      rbuf->buffer_pos = rbuf->buffer;
      rbuf->buffer_left = 0;
      res = iread (rbuf->fd, rbuf->buffer, sizeof (rbuf->buffer));
      if (res <= 0)
	return res;
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
int header_get (struct rbuf *rbuf, char **hdr, enum header_get_flags flags)
{
  int i;
  int bufsize = 80;

  *hdr = (char *)malloc (bufsize);
  if (*hdr == NULL) {
    printf("malloc failed\n");
    exit(-1);
  }
  for (i = 0; 1; i++)
    {
      int res;
      if (i > bufsize - 1)
	*hdr = (char *)xrealloc (*hdr, (bufsize <<= 1));
      res = RBUF_READCHAR (rbuf, *hdr + i);
      if (res == 1)
	{
	  if ((*hdr)[i] == '\n')
	    {
	      if (!((flags & HG_NO_CONTINUATIONS)
		    || i == 0
		    || (i == 1 && (*hdr)[0] == '\r')))
		{
		  char next;
		  /* If the header is non-empty, we need to check if
		     it continues on to the other line.  We do that by
		     peeking at the next character.  */
		  res = rbuf_peek (rbuf, &next);
		  if (res == 0)
		    return HG_EOF;
		  else if (res == -1)
		    return HG_ERROR;
		  /*  If the next character is HT or SP, just continue.  */
		  if (next == '\t' || next == ' ')
		    continue;
		}
	      /* The header ends.  */
	      (*hdr)[i] = '\0';
	      /* Get rid of '\r'.  */
	      if (i > 0 && (*hdr)[i - 1] == '\r')
		(*hdr)[i - 1] = '\0';
	      break;
	    }
	}
      else if (res == 0)
	return HG_EOF;
      else
	return HG_ERROR;
    }
  printf("%s\n", *hdr);
  return HG_OK;
}

/* Parse the HTTP status line, which is of format:

   HTTP-Version SP Status-Code SP Reason-Phrase

   The function returns the status-code, or -1 if the status line is
   malformed.  The pointer to reason-phrase is returned in RP.  */
static int parse_http_status_line (const char *line)
{
  /* (the variables must not be named `major' and `minor', because
     that breaks compilation with SunOS4 cc.)  */
  int mjr, mnr, statcode;
  const char *p;

  /* The standard format of HTTP-Version is: `HTTP/X.Y', where X is
     major version, and Y is minor version.  */
  if (strncmp (line, "HTTP/", 5) != 0)
    return -1;
  line += 5;

  /* Calculate major HTTP version.  */
  p = line;
  for (mjr = 0; isdigit(*line); line++)
    mjr = 10 * mjr + (*line - '0');
  if (*line != '.' || p == line)
    return -1;
  ++line;

  /* Calculate minor HTTP version.  */
  p = line;
  for (mnr = 0; isdigit(*line); line++)
    mnr = 10 * mnr + (*line - '0');
  if (*line != ' ' || p == line)
    return -1;
  /* Wget will accept only 1.0 and higher HTTP-versions.  The value of
     minor version can be safely ignored.  */
  if (mjr < 1)
    return -1;
  ++line;

  /* Calculate status code.  */
  if (!(isdigit(*line) && isdigit(line[1]) && isdigit(line[2])))
    return -1;
  statcode = 100 * (*line - '0') + 10 * (line[1] - '0') + (line[2] - '0');

  /* Set up the reason phrase pointer.  */
  line += 3;
  /* RFC2068 requires SPC here, but we allow the string to finish
     here, in case no reason-phrase is present.  */
  if (*line != ' ')
    {
      if (!*line)
    printf("Reason: %s\n", line);
      else
	return -1;
    }
  else
    printf("Reason: %s\n", line + 1);

  return statcode;
}

/* Skip LWS (linear white space), if present.  Returns number of
   characters to skip.  */
int skip_lws (const char *string)
{
  const char *p = string;

  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
    ++p;
  return p - string;
}

/* Check whether HEADER begins with NAME and, if yes, skip the `:' and
   the whitespace, and call PROCFUN with the arguments of HEADER's
   contents (after the `:' and space) and ARG.  Otherwise, return 0.  */
int header_process (const char *header, const char *name,
		int (*procfun) (const char *, void *),
		void *arg)
{
  /* Check whether HEADER matches NAME.  */
  while (*name && (tolower (*name) == tolower (*header)))
    ++name, ++header;
  if (*name || *header++ != ':')
    return 0;

  header += skip_lws (header);

  return ((*procfun) (header, arg));
}

int header_extract_number (const char *header, void *closure)
{
  const char *p = header;
  long result;

  for (result = 0; isdigit(*p); p++)
    result = 10 * result + (*p - '0');
  if (*p)
    return 0;

  *(long *)closure = result;
  return 1;
}

/* Strdup HEADER, and place the pointer to CLOSURE.  */
int header_strdup (const char *header, void *closure)
{
    int len;
    char *p;

    len = strlen(header) + 1;
    p = malloc(len);
    if (p == NULL) {
        printf("Malloc failed\n");
        exit(-1);
    }
    memset(p, len, 0);
    strcpy(p, header);

  *(char **)closure = p;
  return 1;
}

/* Place 1 to ARG if the HDR contains the word "none", 0 otherwise.
   Used for `Accept-Ranges'.  */
static int http_process_none (const char *hdr, void *arg)
{
  int *where = (int *)arg;

  if (strstr (hdr, "none"))
    *where = 1;
  else
    *where = 0;
  return 1;
}


/* Parse the `Content-Range' header and extract the information it
   contains.  Returns 1 if successful, -1 otherwise.  */
static int http_process_range (const char *hdr, void *arg)
{
  struct http_process_range_closure *closure
    = (struct http_process_range_closure *)arg;
  long num;

  /* Certain versions of Nutscape proxy server send out
     `Content-Length' without "bytes" specifier, which is a breach of
     RFC2068 (as well as the HTTP/1.1 draft which was current at the
     time).  But hell, I must support it...  */
  if (!strncasecmp (hdr, "bytes", 5))
    {
      hdr += 5;
      hdr += skip_lws (hdr);
      if (!*hdr)
	return 0;
    }
  if (!isdigit(*hdr))
    return 0;
  for (num = 0; isdigit(*hdr); hdr++)
    num = 10 * num + (*hdr - '0');
  if (*hdr != '-' || !isdigit(*(hdr + 1)))
    return 0;
  closure->first_byte_pos = num;
  ++hdr;
  for (num = 0; isdigit(*hdr); hdr++)
    num = 10 * num + (*hdr - '0');
  if (*hdr != '/' || !isdigit(*(hdr + 1)))
    return 0;
  closure->last_byte_pos = num;
  ++hdr;
  for (num = 0; isdigit(*hdr); hdr++)
    num = 10 * num + (*hdr - '0');
  closure->entity_length = num;
  return 1;
}

/* HTTP/1.0 status codes from RFC1945, provided for reference.  */
/* Successful 2xx.  */
#define HTTP_STATUS_OK			200
#define HTTP_STATUS_CREATED		201
#define HTTP_STATUS_ACCEPTED		202
#define HTTP_STATUS_NO_CONTENT		204
#define HTTP_STATUS_PARTIAL_CONTENTS	206

/* Redirection 3xx.  */
#define HTTP_STATUS_MULTIPLE_CHOICES	300
#define HTTP_STATUS_MOVED_PERMANENTLY	301
#define HTTP_STATUS_MOVED_TEMPORARILY	302
#define HTTP_STATUS_NOT_MODIFIED	304

/* Client error 4xx.  */
#define HTTP_STATUS_BAD_REQUEST		400
#define HTTP_STATUS_UNAUTHORIZED	401
#define HTTP_STATUS_FORBIDDEN		403
#define HTTP_STATUS_NOT_FOUND		404

/* Server errors 5xx.  */
#define HTTP_STATUS_INTERNAL		500
#define HTTP_STATUS_NOT_IMPLEMENTED	501
#define HTTP_STATUS_BAD_GATEWAY		502
#define HTTP_STATUS_UNAVAILABLE		503
#define H_20X(x)        (((x) >= 200) && ((x) < 300))
#define H_PARTIAL(x)    ((x) == HTTP_STATUS_PARTIAL_CONTENTS)
#define H_REDIRECTED(x) (((x) == HTTP_STATUS_MOVED_PERMANENTLY)	\
			 || ((x) == HTTP_STATUS_MOVED_TEMPORARILY))
			 
#define RBUF_FD(rbuf) ((rbuf)->fd)
#define TEXTHTML_S "text/html"

/* Reset the internal timer.  */
void reset_timer (void)
{
  struct timeval t;
  gettimeofday (&t, NULL);
  internal_secs = t.tv_sec;
  internal_msecs = t.tv_usec / 1000;
}

long elapsed_time (void)
{
  struct timeval t;
  gettimeofday (&t, NULL);
  return ((t.tv_sec - internal_secs) * 1000
	  + (t.tv_usec / 1000 - internal_msecs));
}


/* Flags for show_progress().  */
enum spflags { SP_NONE, SP_INIT, SP_FINISH };

/* The smaller value of the two.  */
#define MINVAL(x, y) ((x) < (y) ? (x) : (y))

/* Flush RBUF's buffer to WHERE.  Flush MAXSIZE bytes at most.
   Returns the number of bytes actually copied.  If the buffer is
   empty, 0 is returned.  */
int
rbuf_flush (struct rbuf *rbuf, char *where, int maxsize)
{
  if (!rbuf->buffer_left)
    return 0;
  else
    {
      int howmuch = MINVAL (rbuf->buffer_left, maxsize);

      if (where)
	memcpy (where, rbuf->buffer_pos, howmuch);
      rbuf->buffer_left -= howmuch;
      rbuf->buffer_pos += howmuch;
      return howmuch;
    }
}

static void print_percentage(long bytes, long expected)
{
  int percentage = (int)(100.0 * bytes / expected);
  printf(" [%3d%%]", percentage);
}

/* Show the dotted progress report of file loading.  Called with
   length and a flag to tell it whether to reset or not.  It keeps the
   offset information in static local variables.

   Return value: 1 or 0, designating whether any dots have been drawn.

   If the init argument is set, the routine will initialize.

   If the res is non-zero, res/line_bytes lines are skipped
   (meaning the appropriate number ok kilobytes), and the number of
   "dots" fitting on the first line are drawn as ','.  */
static int show_progress (long res, long expected, enum spflags flags)
{
  static long line_bytes;
  static long offs;
  static int ndot, nrow;
  int any_output = 0;
  int dots_in_line = 48;
  int dot_spacing = 16;
  int dot_bytes = 8192;

  if (flags == SP_FINISH)
    {
      if (expected)
	{
	  int dot = ndot;
	  char *tmpstr = (char *)alloca (2 * dots_in_line + 1);
	  char *tmpp = tmpstr;
	  for (; dot < dots_in_line; dot++)
	    {
	      if (!(dot % dot_spacing))
		*tmpp++ = ' ';
	      *tmpp++ = ' ';
	    }
	  *tmpp = '\0';
	  printf("%s\n", tmpstr);
	  print_percentage (nrow * line_bytes + ndot * dot_bytes + offs,
			    expected);
	}
      printf("\n\n");
      return 0;
    }

  /* Temporarily disable flushing.  */
  /* init set means initialization.  If res is set, it also means that
     the retrieval is *not* done from the beginning.  The part that
     was already retrieved is not shown again.  */
  if (flags == SP_INIT)
    {
      /* Generic initialization of static variables.  */
      offs = 0L;
      ndot = nrow = 0;
      line_bytes = (long)dots_in_line * dot_bytes;
      if (res)
	{
	  if (res >= line_bytes)
	    {
	      nrow = res / line_bytes;
	      res %= line_bytes;
	      printf("\n          [ skipping %dK ]", (int) ((nrow * line_bytes) / 1024));
	      ndot = 0;
	    }
	}
      printf("\n%5ldK ->", nrow * line_bytes / 1024);
    }
  /* Offset gets incremented by current value.  */
  offs += res;
  /* While offset is >= opt.dot_bytes, print dots, taking care to
     precede every 50th dot with a status message.  */
  for (; offs >= dot_bytes; offs -= dot_bytes)
    {
      if (!(ndot % dot_spacing))
	printf(" ");
      any_output = 1;
      printf("%s", flags == SP_INIT ? "," : ".");
      ++ndot;
      if (ndot == dots_in_line)
	{
	  ndot = 0;
	  ++nrow;
	  if (expected)
	    print_percentage (nrow * line_bytes, expected);
	  printf("\n%5ldK ->", nrow * line_bytes / 1024);
	}
    }
  /* Reenable flushing.  */
  if (any_output)
    ;
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
int get_contents (int fd, FILE *fp, long *len, long restval, long expected,
	      struct rbuf *rbuf)
{
  int res;
  static char c[8192];

  *len = restval;
  show_progress (restval, expected, SP_INIT);
  if (rbuf && RBUF_FD (rbuf) == fd)
    {
      while ((res = rbuf_flush (rbuf, c, sizeof (c))) != 0)
	{
	  if (fwrite(c, sizeof (char), res, fp) < res)
	    return -2;
      show_progress (res, expected, SP_NONE);
      fflush (fp);
	  *len += res;
	}
    }
  /* Read from fd while there is available data.  */
  do
    {
      res = iread (fd, c, sizeof (c));
      if (res > 0)
	{
	  if (fwrite(c, sizeof (char), res, fp) < res)
	    return -2;
      show_progress (res, expected, SP_NONE);
      fflush (fp);
	  *len += res;
	}
    } while (res > 0);
  if (res < -1)
    res = -1;
  show_progress (0, expected, SP_FINISH);
  printf("Finish\n");
  return res;
}

static int gethttp (struct urlinfo *u, struct http_stat *hs, int *dt)
{
  char *request, *command, *path;
  char *pragma_h, *referer, *useragent, *range, *remhost;
  char *all_headers;
  int lh;
  int sock, hcount, num_written, all_length, remport, statcode;
  long contlen, contrange;
  struct urlinfo *ou;
  uerr_t err;
  FILE *fp;
  struct rbuf rbuf;

  /* Initialize certain elements of struct hstat.  */
  hs->len = 0L;
  hs->contlen = -1;
  hs->res = -1;
  hs->remote_time = NULL;
  hs->error = NULL;

  /* Which structure to use to retrieve the original URL data.  */

  ou = u;

  /* First: establish the connection.  */
  printf("Connecting to %s:%hu...\n", u->host, u->port);
  err = make_connection (&sock, u->host, u->port);
  switch (err)
    {
    case HOSTERR:
      return HOSTERR;
      break;
    case CONSOCKERR:
      printf("socket: %s\n", strerror(errno));
      return CONSOCKERR;
      break;
    case CONREFUSED:
      printf ("Connection to %s:%hu refused.\n", u->host, u->port);
      close(sock);
      return CONREFUSED;
    case CONERROR:
      printf("connect: %s\n", strerror(errno));
      close(sock);
      return CONERROR;
      break;
    case NOCONERROR:
      /* Everything is fine!  */
      printf("connected!\n");
      break;
    default:
      abort ();
      break;
    } /* switch */

  path = u->path;
  command = "GET";
  referer = NULL;
  if (ou->referer)
    {
      referer = (char *)alloca (9 + strlen (ou->referer) + 3);
      sprintf (referer, "Referer: %s\r\n", ou->referer);
    }
  if (*dt & SEND_NOCACHE)
    pragma_h = "Pragma: no-cache\r\n";
  else
    pragma_h = "";
  if (hs->restval)
    {
      range = (char *)alloca (13 + numdigit (hs->restval) + 4);
      /* #### Gag me!  Some servers (e.g. WebSitePro) have been known
         to misinterpret the following `Range' format, and return the
         document as multipart/x-byte-ranges MIME type!

	 #### TODO: Interpret MIME types, recognize bullshits similar
	 the one described above, and deal with them!  */
      sprintf (range, "Range: bytes=%ld-\r\n", hs->restval);
    }
  else
    range = NULL;
  
  useragent = (char *)alloca (10 + strlen (version_string));
  sprintf (useragent, "Wget/%s", version_string);

  remhost = ou->host;
  remport = ou->port;
  /* Allocate the memory for the request.  */
  request = (char *)alloca (strlen (command) + strlen (path)
			    + strlen (useragent)
			    + strlen (remhost) + numdigit (remport)
			    + strlen (HTTP_ACCEPT)
			    + (referer ? strlen (referer) : 0)
			    + (range ? strlen (range) : 0)
			    + strlen (pragma_h)
			    + 64);
  /* Construct the request.  */
  sprintf (request, "\
%s %s HTTP/1.0\r\n\
User-Agent: %s\r\n\
Host: %s:%d\r\n\
Accept: %s\r\n\
%s%s%s\r\n",
	  command, path, useragent, remhost, remport, HTTP_ACCEPT, 
	  referer ? referer : "", 
	  range ? range : "",
	  pragma_h);
  printf("---request begin---\n%s---request end---\n", request);

  /* Send the request to server.  */
  num_written = iwrite (sock, request, strlen (request));
  if (num_written < 0)
    {
      printf("Failed writing HTTP request.\n");
      free(request);
      close(sock);
      return WRITEFAILED;
    }
  printf("HTTP request sent, awaiting response... ");
  contlen = contrange = -1;
  statcode = -1;
  *dt &= ~RETROKF;

  /* Before reading anything, initialize the rbuf.  */
  rbuf_initialize (&rbuf, sock);

  all_headers = NULL;
  all_length = 0;
  /* Header-fetching loop.  */
  hcount = 0;
  while (1)
    {
      char *hdr;
      int status;

      ++hcount;
      /* Get the header.  */
      status = header_get (&rbuf, &hdr,
			   /* Disallow continuations for status line.  */
			   (hcount == 1 ? HG_NO_CONTINUATIONS : HG_NONE));

      /* Check for errors.  */
      if (status == HG_EOF && *hdr)
	{
	  /* This used to be an unconditional error, but that was
             somewhat controversial, because of a large number of
             broken CGI's that happily "forget" to send the second EOL
             before closing the connection of a HEAD request.

	     So, the deal is to check whether the header is empty
	     (*hdr is zero if it is); if yes, it means that the
	     previous header was fully retrieved, and that -- most
	     probably -- the request is complete.  "...be liberal in
	     what you accept."  Oh boy.  */
	  printf("End of file while parsing headers.\n");
	  free(hdr);
	  FREE_MAYBE (all_headers);
	  close(sock);
	  return HEOF;
	}
      else if (status == HG_ERROR)
	{
	  printf("Read error (%s) in headers.\n",strerror(errno));
	  free(hdr);
	  FREE_MAYBE(all_headers);
	  close(sock);
	  return HERR;
	}

      /* If the headers are to be saved to a file later, save them to
	 memory now.  */
	  lh = strlen (hdr);
	  all_headers = (char *)xrealloc (all_headers, all_length + lh + 2);
	  memcpy (all_headers + all_length, hdr, lh);
	  all_length += lh;
	  all_headers[all_length++] = '\n';
	  all_headers[all_length] = '\0';

      /* Print the header if requested.  */
	printf("\n%d %s", hcount, hdr);

      /* Check for status line.  */
      if (hcount == 1)
	{
	  /* Parse the first line of server response.  */
	  statcode = parse_http_status_line (hdr);
	  hs->statcode = statcode;
	  /* Store the descriptive response.  */
	  if (statcode == -1) /* malformed response */
	    {
	      /* A common reason for "malformed response" error is the
                 case when no data was actually received.  Handle this
                 special case.  */
	      if (!*hdr)
		hs->error = "No data received";
	      else
		hs->error = "Malformed status line";
	      free (hdr);
	      break;
	    }
	  else
	    hs->error = "(no description)";

	  if (statcode != -1)
	    printf("status code: %d\n", statcode);

	  goto done_header;
	}

      /* Exit on empty header.  */
      if (!*hdr)
	{
	  free (hdr);
	  break;
	}

      /* Try getting content-length.  */
      if (contlen == -1)
	if (header_process (hdr, "Content-Length", header_extract_number,
			    &contlen))
	  goto done_header;
      /* Try getting last-modified.  */
      if (!hs->remote_time)
	if (header_process (hdr, "Last-Modified", header_strdup,
			    &hs->remote_time))
	  goto done_header;
      /* Check for accept-ranges header.  If it contains the word
	 `none', disable the ranges.  */
      if (*dt & ACCEPTRANGES)
	{
	  int nonep;
	  if (header_process (hdr, "Accept-Ranges", http_process_none, &nonep))
	    {
	      if (nonep)
		*dt &= ~ACCEPTRANGES;
	      goto done_header;
	    }
	}
      /* Try getting content-range.  */
      if (contrange == -1)
	{
	  struct http_process_range_closure closure;
	  if (header_process (hdr, "Content-Range", http_process_range, &closure))
	    {
	      contrange = closure.first_byte_pos;
	      goto done_header;
	    }
	}
    done_header:
      free (hdr);
    }

  printf("\n");

  /* 20x responses are counted among successful by default.  */
  if (H_20X (statcode)) {
    printf("%s<%d>\n", __func__, __LINE__);
    *dt |= RETROKF;
  }

  if (contrange == -1)
    hs->restval = 0;
  else if (contrange != hs->restval ||
	   (H_PARTIAL (statcode) && contrange == -1))
    {
      /* This means the whole request was somehow misunderstood by the
	 server.  Bail out.  */
      FREE_MAYBE (all_headers);
      close(sock);
      return RANGEERR;
    }

  if (hs->restval)
    {
      if (contlen != -1)
	contlen += contrange;
      else
	contrange = -1;        /* If conent-length was not sent,
				  content-range will be ignored.  */
    }
  hs->contlen = contlen;

  /* Return if redirected.  */
  if (H_REDIRECTED (statcode) || statcode == HTTP_STATUS_MULTIPLE_CHOICES)
    {
        printf("Redirect\n");
    }

  /* Return if we have no intention of further downloading.  */
  if (!(*dt & RETROKF) || (*dt & HEAD_ONLY))
    {
      /* In case someone cares to look...  */
      hs->len = 0L;
      hs->res = 0;
      FREE_MAYBE (all_headers);
      close(sock);
    printf("%s<%d>\n", __func__, __LINE__);
      return RETRFINISHED;
    }

      fp = fopen (u->local, hs->restval ? "ab" : "wb");
      if (!fp)
	{
	  printf("%s: %s\n", u->local, strerror(errno));
	  close(sock);
	  FREE_MAYBE(all_headers);
	  return FOPENERR;
	}

  /* #### This confuses the code that checks for file size.  There
     should be some overhead information.  */
  printf("HEADERS:\n%s\n", all_headers);
  reset_timer();
  /* Get the contents of the document.  */
  hs->res = get_contents (sock, fp, &hs->len, hs->restval,
			  (contlen != -1 ? contlen : 0),
			  &rbuf);
  hs->dltime = elapsed_time ();
  fclose(fp);
  FREE_MAYBE(all_headers);
  close(sock);
  if (hs->res == -2)
    return FWRITEERR;
  return RETRFINISHED;
}

#define BUF_LEN 128

int main(int argc, char *argv[])
{
    int ret;
    struct urlinfo ui;
    struct http_stat hs;
    int dt = 0;
    char host[BUF_LEN], local[BUF_LEN], path[BUF_LEN];
    char *p, *q;

    if (argc != 2 && argc != 3) {
        printf("Usage: %s URL [Referer]\n", argv[0]);
        return -1;
    }

    memset(&ui, sizeof(ui), 0);
    memset(&hs, sizeof(hs), 0);
    bzero(host, BUF_LEN);
    bzero(local, BUF_LEN);
    bzero(path, BUF_LEN);
    dt |= ACCEPTRANGES;

    if (strstr(argv[1], "http://") != NULL) {
        q = argv[1] + 7;
    } else {
        q = argv[1];
    }
    for (p = host; p < host + BUF_LEN - 1; p++, q++) {
        if ((isdigit(*q)) || (*q == '.')) {
            *p = *q;
        } else {
            break;
        }
    }
    for (p = path; p < path + BUF_LEN - 1; p++, q++) {
        if (*q == '\n' || *q == '\0' || *q == ' ') {
            break;
        } else {
            *p = *q;
        }
    }
    q = argv[1] + strlen(argv[1]);
    for ( ; *q != '/' && q > argv[1]; q--) {
        (void)0;
    }
    for (p = local, q = q + 1; p < local + BUF_LEN -1; p++, q++) {
        if (*q == '\n' || *q == '\0' || *q == ' ') {
            break;
        } else {
            *p = *q;
        }
    }

    ui.url = argv[1];
    ui.host = host;
    ui.local = local;
    ui.path = path;
    ui.port = 80;
    if (argc == 3) {
        ui.referer = argv[2];
    }

    ret = gethttp(&ui, &hs, &dt);

    printf("gethttp return %d\n", ret);
    printf("HS error: %s\n", hs.error);
    printf("HS delta time: %ld\n", hs.dltime);
    printf("HS content length: %ld, %ld\n", hs.contlen, hs.len);
    printf("HS remote time: %s\n", hs.remote_time);
    printf("HS status code: %d\n", hs.statcode);

    return 0;
}

