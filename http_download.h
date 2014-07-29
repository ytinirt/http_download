#ifndef __HTTP_DOWNLOAD_H__
#define __HTTP_DOWNLOAD_H__

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

/* Flags for show_progress().  */
enum spflags { SP_NONE, SP_INIT, SP_FINISH };

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

#define BUF_LEN 128

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

/* The smaller value of the two.  */
#define MINVAL(x, y) ((x) < (y) ? (x) : (y))

#endif /* __HTTP_DOWNLOAD_H__ */

