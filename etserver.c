/* EtServer - a low-memory-footprint web server for serving static content
 * Originally made by: EthernetLord
 * - https://github.com/ethernetlord
 * - https://ethernetlord.eu/
 * This program is an open source software licensed under GNU General Public License v3.0.
 */



#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>
#include<stdarg.h>
#include<pthread.h>
#include<limits.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<errno.h>
#include<unistd.h>
#include<sys/stat.h>
#include<time.h>
#include<ctype.h>





/****************************************
 *   ~~~   CONSTANT DEFINITIONS   ~~~   *
 ****************************************/

#define WS_SOCKET_TIMEOUT 10 // the number of seconds the connection will last without any activity
#define WS_XSS_CHARACTERS "&\"'<>" // characters, that might be unsafe to be placed to the redirect page (refer to the ws_filepath_can_cause_xss() function)
#define WS_SERVERFP "EtServer/0.1" // this will be shown in the Server HTTP header and error messages
#define WS_LISTEN_QUEUE 5 // second parameter for the listen() function
#define WS_SEND_BUFSIZE 8192 // buffer size (allocated on stack) that will be used to fread() and send() the file to the client
#define WS_HTTPDATE_BUFFER_LEN 64 // size of a buffer used when calling the strftime() function (used when sending Date and Last-Modified HTTP headers)

// max length of the first line of received HTTP request (next lines aren't recieved at all)
// ~ there is no need to have this bigger than PATH_MAX + a few bytes
// ~ even if you set it to a huge value, it will be limited by the max size of a single recv() call, which is 16384 in my case
#define WS_REQUEST_MAXLEN 5120



// HTML that will be sent when the server will encounter an HTTP error
#define WS_HTTPERR_400 "<html><head>\
<meta charset=\"UTF-8\">\
<title>400 Bad Request</title>\
</head><body>\
<h1>400 Bad Request</h1>\
<p>The server wasn't able to process your request, because it was malformed or incomplete.</p>\
<hr>\
<i>"WS_SERVERFP"</i>\
</body></html>"

#define WS_HTTPERR_403 "<html><head>\
<meta charset=\"UTF-8\">\
<title>403 Forbidden</title>\
</head><body>\
<h1>403 Forbidden</h1>\
<p>You aren't allowed to access this resource on this server.</p>\
<hr>\
<i>"WS_SERVERFP"</i>\
</body></html>"

#define WS_HTTPERR_404 "<html><head>\
<meta charset=\"UTF-8\">\
<title>404 Not Found</title>\
</head><body>\
<h1>404 Not Found</h1>\
<p>The resourse you're trying to access isn't available on this server.</p>\
<hr>\
<i>"WS_SERVERFP"</i>\
</body></html>"

#define WS_HTTPERR_414 "<html><head>\
<meta charset=\"UTF-8\">\
<title>414 URI Too Long</title>\
</head><body>\
<h1>414 URI Too Long</h1>\
<p>The URI of the resource you're trying to access is too long to be processed correctly.</p>\
<hr>\
<i>"WS_SERVERFP"</i>\
</body></html>"

#define WS_HTTPERR_501 "<html><head>\
<meta charset=\"UTF-8\">\
<title>501 Not Implemented</title>\
</head><body>\
<h1>501 Not Implemented</h1>\
<p>The HTTP request method your browser has specified in the request is not supported by the server.</p>\
<hr>\
<i>"WS_SERVERFP"</i>\
</body></html>"

#define WS_HTTPERR_505 "<html><head>\
<meta charset=\"UTF-8\">\
<title>505 HTTP Version Not Supported</title>\
</head><body>\
<h1>505 HTTP Version Not Supported</h1>\
<p>The version of the HTTP protocol your browser is asking in isn't supported by this server.</p>\
<hr>\
<i>"WS_SERVERFP"</i>\
</body></html>"

#define WS_HTTPERR_500 "<html><head>\
<meta charset=\"UTF-8\">\
<title>500 Internal Server Error</title>\
</head><body>\
<h1>500 Internal Server Error</h1>\
<p>The server wasn't able to process your request due to an internal error.</p>\
<hr>\
<i>"WS_SERVERFP"</i>\
</body></html>"

#define WS_HTTPERR_302_SPRINTF "<html><head>\
<meta charset=\"UTF-8\">\
<title>302 Found</title>\
</head><body>\
<h1>302 Found</h1>\
<p>You will be redirected soon. If nothing happens, <a href=\"%s\">click here</a>.</p>\
<hr>\
<i>"WS_SERVERFP"</i>\
</body></html>"



// global constant that will be used when applying timeout to client's socket
const struct timeval CLIENT_TIMEOUT = {WS_SOCKET_TIMEOUT, 0};



// the database of MIME types the server supports for the "Content-Type" HTTP headers
// the array needs to have an even number of elements, where:
// ~ the element with even index is a lowercase file extension used for detecting the type
// ~ the element with odd index is the MIME type itself
// if you add new MIME types, make sure that they aren't longer than the limit of this array! (including the null-terminator, of course)
const char WS_MIME_DB[][80] = {
  "html", "text/html",
  "txt", "text/plain",
  "css", "text/css",
  "js", "application/javascript",
  "xml", "application/xml",
  "xhtml", "application/xhtml+xml",
  "json", "application/json",
  "csv", "text/csv",
  "tsv", "text/tab-separated-values",
  "ico", "image/x-icon",
  "gif", "image/gif",
  "jpg", "image/jpeg",
  "png", "image/png",
  "bmp", "image/bmp",
  "svg", "image/svg+xml",
  "tiff", "image/tiff",
  "zip", "application/zip",
  "rar", "application/x-rar-compressed",
  "gz", "application/gzip",
  "bz2", "application/x-bzip2",
  "xz", "application/x-xz",
  "tar", "application/x-tar",
  "7z", "application/x-7z-compressed",
  "mp3", "audio/mpeg",
  "ogg", "audio/ogg",
  "wav", "audio/wav",
  "flac", "audio/flac",
  "wma", "audio/x-ms-wma",
  "mid", "audio/x-midi",
  "mp4", "video/mp4",
  "avi", "video/avi",
  "wmv", "video/x-ms-asf",
  "webm", "video/webm",
  "doc", "application/msword",
  "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "xls", "application/vns.ms-excel",
  "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "ppt", "application/vnd.ms-powerpoint",
  "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "pdf", "application/pdf",
  "rtf", "application/rtf"
};
// in case any appropriate MIME type wasn't found in WS_MIME_DB, send this MIME type
const char WS_DEFAULT_MIME[] = "application/octet-stream";





/***************************************
 *   ~~~   STRUCT DEFINITIONS   ~~~    *
 ***************************************/

typedef struct {
  const char *serve_dir;
  const char *dir_index;
  int client_sockfd;
} WS_THREAD_ARGS;

typedef struct {
  char *method;
  char *filepath;
  char *http_ver;
  struct stat file_stat;
} WS_REQUEST;










/***********************************************
 *   ~~~   AUXILIARY FUNCTIONS SECTION   ~~~   *
 ***********************************************/

// printf() wrapper function used to crash the program and report the error to stderr in case of a problem
// it shouldn't be used while processing the client request, because client shouldn't be able to crash the program
void ws_crashprintf(const bool do_perror, const char *format, ...) {
  va_list va;

  va_start(va, format);
  fputs("[ERROR] ", stderr);
  vfprintf(stderr, format, va);
  fputc('\n', stderr);
  va_end(va);

  if(do_perror) perror("Error description");
  exit(EXIT_FAILURE);
}

// print the program name, version and the order of the arguments used to run the program
// printed in case of a invalid number of arguments passed to the program (argc)
void ws_usage(void) {
  fputs("--- Web server " WS_SERVERFP " ---\n", stderr);
  fputs("Arguments:\n", stderr);
  fputs("\t1. IP address to listen\n", stderr);
  fputs("\t2. TCP port number to listen\n", stderr);
  fputs("\t3. Path to serve files from\n", stderr);
  fputs("\t4. Directory index filename\n", stderr);
}

// converts the number of seconds since 1 Jan 1970 to the datetime format used in HTTP headers like Date and Last-Modified
void ws_unixtime_to_httpdate(char *where, const time_t unix_time) {
  struct tm tmstruct;
  gmtime_r(&unix_time, &tmstruct);
  strftime(where, WS_HTTPDATE_BUFFER_LEN, "%a, %d %b %Y %H:%M:%S GMT", &tmstruct);
}

// auxiliary function
bool ws_send_http_header(const char *key, const char *value, const int client_sockfd) {
  return (bool) (
    send(client_sockfd, key, strlen(key), 0) <= 0 ||
    send(client_sockfd, ": ", 2, 0) <= 0 ||
    send(client_sockfd, value, strlen(value), 0) <= 0 ||
    send(client_sockfd, "\r\n", 2, 0) <= 0
  );
}

// auxiliary function
bool ws_check_supported_http_ver(const char *version) {
  return (bool) (version != NULL && (!strcmp(version, "HTTP/1.0") || !strcmp(version, "HTTP/1.1")));
}

// auxiliary function
bool ws_check_supported_http_method(const char *method) {
  return (bool) (method != NULL && (!strcmp(method, "GET") || !strcmp(method, "HEAD")));
}

// returns a pointer to a null-terminated string with the MIME type of a file detected by it's extension
const char *ws_get_file_mimetype(char *filename) {
  char *search_temp;

  // move the string pointer to the file extension part
  while((search_temp = strchr(filename, '.')) != NULL) filename = (search_temp + 1);

  // canonilize the file extension
  for(search_temp = filename; *search_temp != '\0'; search_temp++) {
    //if(*search_temp >= 65 && *search_temp <= 90) *search_temp += 32;
    *search_temp = tolower(*search_temp);
  }

  size_t i;
  // go through the database of known MIME types and return an appropriate one, if found
  for(i = 0; i < (sizeof(WS_MIME_DB) / sizeof(WS_MIME_DB[0])); i += 2) {
    if(!strcmp(filename, WS_MIME_DB[i])) return (WS_MIME_DB[i + 1]);
  }

  // if no MIME type was found in the DB, return the default one
  return WS_DEFAULT_MIME;
}

// auxiliary function
bool ws_is_char_hex(const char c) {
  // ASCII table - hex chars:
  // ~ 48 to 57 (0x30 to 0x39) - '0' to '9'
  // ~ 65 to 70 (0x41 to 0x46) - 'A' to 'F'
  // ~ 97 to 102 (0x61 to 0x66) - 'a' to 'f' (since URL percent-encoding is case-insensitive)
  return (bool) !((c < '0' || c > '9') && (c < 'A' || c > 'F') && (c < 'a' || c > 'f'));
}

// decodes the percent-encoded data
// the function modifies the source specified by the first argument
// it doesn't decode "%00", because that would end the null-terminated string before the actual end
void ws_urldecode(char *str) {
  // in-place URL-decoding would be crazy :-)
  char old[strlen(str) + 1];
  strcpy(old, str);

  size_t i;
  for(i = 0; old[i] != '\0'; str++) {
    if(old[i] == '%' && ws_is_char_hex(old[i+1]) && ws_is_char_hex(old[i+2]) && (old[i+1] != '0' || old[i+2] != '0')) {
      // in case of a valid URL-encoded value was found in the string, canonilize the hex chars so the next condition can be simpler
      old[i+1] = toupper(old[i+1]);
      old[i+2] = toupper(old[i+2]);
      // get the decoded ASCII value
      *str = (old[i+1] < 'A' ? old[i+1] - 48 : old[i+1] - 55) * 16;
      *str += (old[i+2] < 'A' ? old[i+2] - 48 : old[i+2] - 55);
      // skip to the next char after the percent-encoded value
      i += 3;
    } else {
      // copy the char to the destination and continue, if no valid percent-encoded byte was found
      *str = old[i++];
    }
  }

  // terminate the decoded string, because if any percent-encoded bytes were found, the resultant string will be shorter than the original one
  *str = '\0';
}

// percent encodes data specified in src and writes them to dst
// dst should be at least strlen(src) * 3 + 1 bytes long!!! (in worst possible case - all characters must be urlencoded - it will be fully filled)
// it doesn't allocate any memory (for clarity)
void ws_urlencode(char *dst, const char *src) {
  while(*src != '\0') {
    // all characters except 0-9A-Za-z-_.~ must be URLencoded (if in single URL part)
    if((*src < '0' || *src > '9') && (*src < 'A' || *src > 'Z') && (*src < 'a' || *src > 'z') && *src != '-' && *src != '_' && *src != '.' && *src != '~') {
      // if character must be urlencoded, get the percent-encoded value via sprintf (including the percent sign, uppercase)
      sprintf(dst, "%%%2hhX", *src++);
      dst += 3;
    } else {
      // otherwise, just copy the original one
      *dst++ = *src++;
    }
  }
  *dst = '\0';
}










/**********************************
 *   ~~~   SOCKET SECTION   ~~~   *
 **********************************/

// prepend the IPv4 to IPv6 mapped address prefix to an IPv4 address to simplify the socket creation process
// kind of hacky, but working well :-)
void ws_convert_4to6_mapped(char *dst, const char *src) {
  if(strchr(src, ':') != NULL) {
    strcpy(dst, src);
    return;
  }

  memcpy(dst, "::ffff:", 7);
  strcpy(dst + 7, src);
}

// convert the address and port entered in command line arguments and enter them to the sockaddr_in6 struct
void ws_prepare_addr(struct sockaddr_in6 *addr, const char *c_addr, const char *c_port) {
  unsigned short port = (unsigned short) atoi(c_port);
  if(port == 0 && strcmp(c_port, "0")) ws_crashprintf(false, "Bad listen port! (%s)", c_port);

  char converted_c_addr[strlen(c_addr) + 8];
  ws_convert_4to6_mapped(converted_c_addr, c_addr);

  addr->sin6_family = AF_INET6;
  if(!inet_pton(AF_INET6, converted_c_addr, &addr->sin6_addr)) ws_crashprintf(false, "Bad listen address! (%s)", c_addr);
  addr->sin6_port = htons(port);

  // initialize those values to 0, so valgrind doesn't complain :-)
  addr->sin6_flowinfo = 0;
  addr->sin6_scope_id = 0;
}

// create, bind and mark the socket as listening using the struct sockaddr_in6 and return the file descriptor
int ws_configure_sock(struct sockaddr_in6 *addr) {
  int sockfd;

  if((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) ws_crashprintf(true, "Couldn't create socket!");
  if(bind(sockfd, (struct sockaddr *) addr, sizeof(struct sockaddr_in6)) < 0) ws_crashprintf(true, "Couldn't bind socket!");
  if(listen(sockfd, WS_LISTEN_QUEUE) < 0) ws_crashprintf(true, "Couldn't mark socket as listening!");

  return sockfd;
}

// close a socket and crash the program in case of a failure and the crash parameter set to true
void ws_close_sock(int sockfd, bool crash) {
  if(close(sockfd) < 0 && crash) ws_crashprintf(true, "Couldn't close socket!");
}










/****************************************************
 *   ~~~   HTTP RESPONSE PROCESSING SECTION   ~~~   *
 ****************************************************/

bool ws_send_response_first_line(const int client_sockfd, const char *http_ver, short response_code) {
  char code_text[32];

  // get the text representation of the HTTP status code
  switch(response_code) {
    case 200: strcpy(code_text, "OK"); break;
    case 302: strcpy(code_text, "Found"); break;
    case 400: strcpy(code_text, "Bad Request"); break;
    case 403: strcpy(code_text, "Forbidden"); break;
    case 404: strcpy(code_text, "Not Found"); break;
    case 414: strcpy(code_text, "URI Too Long"); break;
    case 501: strcpy(code_text, "Not Implemented"); break;
    case 505: strcpy(code_text, "HTTP Version Not Supported"); break;
    default: response_code = 500; strcpy(code_text, "Internal Server Error"); break;
  }

  // convert the status code to string, so it can be sent
  char response_code_char[4];
  sprintf(response_code_char, "%hd", response_code);

  // the actual sending of the first line
  if(
    send(client_sockfd, ws_check_supported_http_ver(http_ver) ? http_ver : "HTTP/1.0", ws_check_supported_http_ver(http_ver) ? strlen(http_ver) : 8, 0) <= 0 ||
    send(client_sockfd, " ", 1, 0) <= 0 ||
    send(client_sockfd, response_code_char, strlen(response_code_char), 0) <= 0 ||
    send(client_sockfd, " ", 1, 0) <= 0 ||
    send(client_sockfd, code_text, strlen(code_text), 0) <= 0 ||
    send(client_sockfd, "\r\n", 2, 0) <= 0
  ) return false;

  return true;
}

bool ws_send_response_headers(const int client_sockfd, const WS_REQUEST *request, const short response_code) {
  char date_buf[WS_HTTPDATE_BUFFER_LEN];
  char filesize_str_buf[24];
  size_t err_msg_length;

  // prepare & send the "Date" HTTP header
  ws_unixtime_to_httpdate(date_buf, time(NULL));
  if(ws_send_http_header("Date", date_buf, client_sockfd)) return false;

  // Connection
  if(ws_send_http_header("Connection", "close", client_sockfd)) return false;

  // Server
  if(ws_send_http_header("Server", WS_SERVERFP, client_sockfd)) return false;

  if(response_code == 200) { // ### headers in case of successful request ###
    // Content-Type
    if(ws_send_http_header("Content-Type", ws_get_file_mimetype(request->filepath), client_sockfd)) return false;

    // Content-Length
    snprintf(filesize_str_buf, 24, "%td", request->file_stat.st_size);
    if(ws_send_http_header("Content-Length", filesize_str_buf, client_sockfd)) return false;

    // Last-Modified
    ws_unixtime_to_httpdate(date_buf, request->file_stat.st_mtime);
    if(ws_send_http_header("Last-Modified", date_buf, client_sockfd)) return false;

  } else { // ### in case of an error... ###
    // Content-Type
    if(ws_send_http_header("Content-Type", "text/html; charset=UTF-8", client_sockfd)) return false;

    // Content-Length
    switch(response_code) {
      // the -2 characters are the "%s" sprintf format specifier in the WS_HTTPERR_302_WITHPATH (it will be replaced with request->filepath later)
      case 302: err_msg_length = strlen(WS_HTTPERR_302_SPRINTF) + strlen(request->filepath) - 2; break;
      case 400: err_msg_length = strlen(WS_HTTPERR_400); break;
      case 403: err_msg_length = strlen(WS_HTTPERR_403); break;
      case 404: err_msg_length = strlen(WS_HTTPERR_404); break;
      case 414: err_msg_length = strlen(WS_HTTPERR_414); break;
      case 501: err_msg_length = strlen(WS_HTTPERR_501); break;
      case 505: err_msg_length = strlen(WS_HTTPERR_505); break;
      default: err_msg_length = strlen(WS_HTTPERR_500); break;
    }

    snprintf(filesize_str_buf, 24, "%zu", err_msg_length);
    if(ws_send_http_header("Content-Length", filesize_str_buf, client_sockfd)) return false;
  }

  // redirect the user if set so
  if(response_code == 302 && ws_send_http_header("Location", request->filepath, client_sockfd)) return false;

  // empty line between the headers and the body
  if(send(client_sockfd, "\r\n", 2, 0) <= 0) return false;

  return true;
}

bool ws_send_error_body(const int client_sockfd, const short response_code) {
  // every implemented HTTP error code has it's own body
  switch(response_code) {
    case 400: if(send(client_sockfd, WS_HTTPERR_400, strlen(WS_HTTPERR_400), 0) <= 0) return false; break;
    case 403: if(send(client_sockfd, WS_HTTPERR_403, strlen(WS_HTTPERR_403), 0) <= 0) return false; break;
    case 404: if(send(client_sockfd, WS_HTTPERR_404, strlen(WS_HTTPERR_404), 0) <= 0) return false; break;
    case 414: if(send(client_sockfd, WS_HTTPERR_414, strlen(WS_HTTPERR_414), 0) <= 0) return false; break;
    case 501: if(send(client_sockfd, WS_HTTPERR_501, strlen(WS_HTTPERR_501), 0) <= 0) return false; break;
    case 505: if(send(client_sockfd, WS_HTTPERR_505, strlen(WS_HTTPERR_505), 0) <= 0) return false; break;
    default: if(send(client_sockfd, WS_HTTPERR_500, strlen(WS_HTTPERR_500), 0) <= 0) return false; break;
  }

  return true;
}

bool ws_send_redirect_body(const int client_sockfd, const char *filepath) {
  size_t send_len = strlen(WS_HTTPERR_302_SPRINTF) + strlen(filepath) - 2; // -2 for the sprintf() "%s" format specified
  char buf[send_len + 1];
  sprintf(buf, WS_HTTPERR_302_SPRINTF, filepath);

  if(send(client_sockfd, buf, send_len, 0) <= 0) return false;

  return true;
}

bool ws_send_response_body(const int client_sockfd, const WS_REQUEST *request, FILE *fp, const short response_code) {
  // do not send the body in case the HTTP method is "HEAD"
  if(request->method != NULL && !strcmp(request->method, "HEAD")) return true;

  size_t bytes_read;
  char buf[WS_SEND_BUFSIZE];

  switch(response_code) {
    case 200: // in case of a successful request, send the requested file
      while((bytes_read = fread(buf, 1, WS_SEND_BUFSIZE, fp)) > 0) {
        if(send(client_sockfd, buf, bytes_read, 0) <= 0) return false;
      }
      break;

    case 302: // in case of a redirect, redirect the user (Who would have guessed that?)
      if(!ws_send_redirect_body(client_sockfd, request->filepath)) return false;
      break;

    default: // in case of an error, send the error body
      if(!ws_send_error_body(client_sockfd, response_code)) return false;
      break;
  }

  return true;
}

void ws_send_response(WS_THREAD_ARGS *args, WS_REQUEST *request, short response_code) {
  FILE *fp = NULL;

  // if the request was successful so far, but we cannot open the requested file or get the file statistics, return "Internal Server Error" HTTP status
  if(response_code == 200 && (fp = fopen(request->filepath, "r")) == NULL) response_code = 500;

  // if we wan't to reply to the request (determined by the response_code value), send the reply
  if(response_code >= 100 && response_code < 1000) (ws_send_response_first_line(args->client_sockfd, request->http_ver, response_code) && ws_send_response_headers(args->client_sockfd, request, response_code) && ws_send_response_body(args->client_sockfd, request, fp, response_code));

  if(fp != NULL) fclose(fp); // close the file if opened before
  ws_close_sock(args->client_sockfd, false); // close the socket and don't crash the program in case it fails (client could timeout for example)
}










/***************************************************
 *   ~~~   HTTP REQUEST PROCESSING SECTION   ~~~   *
 ***************************************************/

bool ws_recv_request(const int client_sockfd, char *request, short *response_code) {
  ssize_t recv_size;

  // only the first line of the request will be received (e.g. GET /file.html HTTP/1.1),
  // because headers and body of the request aren't required for the correct function of this program

  if((recv_size = recv(client_sockfd, request, WS_REQUEST_MAXLEN, 0)) <= 0) {
    // in case of receiving failure, do not send client an reply and just close the connection (even that might not be possible, but nothing bad happens in that case)
    *response_code = -1;
    return false;
  }
  request[recv_size] = '\0';
  if(strlen(request) != recv_size || strchr(request, '\n') == NULL) {
    // the client could put a null character in the request which is something we don't want to see in a text-based protocol such as HTTP
    *response_code = -1;
    return false;
  }

  return true;
}

bool ws_parse_request(WS_REQUEST *request, char *start, short *response_code) {
  char *end;

  // get the REQUEST METHOD
  if((end = strchr(start, ' ')) == NULL) {
    *response_code = 400;
    return false;
  }
  *end = '\0';
  request->method = start;

  // REQUESTED FILE PATH
  start = end + 1;
  if((end = strpbrk(start, "?#; ")) == NULL) {
    *response_code = 400;
    return false;
  }
  // this part of string will be modified later, so we need to allocate it again
  size_t len = (size_t) (end - start);
  request->filepath = calloc(len + 1, 1);
  strncpy(request->filepath, start, len);

  // REQUEST HTTP VERSION
  if((start = strchr(end, ' ')) == NULL || (end = strpbrk(start, "\r\n")) == NULL) {
    *response_code = 400;
    return false;
  }
  *end = '\0';
  request->http_ver = start + 1;

  return true;
}

bool ws_validate_request(const WS_REQUEST *request, short *response_code) {
  // REQUEST METHOD
  if(!ws_check_supported_http_method(request->method)) {
    *response_code = 501;
    return false;
  }

  // REQUEST PATH has to start with the '/' character
  if(*request->filepath != '/') {
    *response_code = 400;
    return false;
  }

  // HTTP VERSION
  if(!ws_check_supported_http_ver(request->http_ver)) {
    *response_code = 505;
    return false;
  }

  return true;
}

bool ws_resolve_filepath(const WS_THREAD_ARGS *args, WS_REQUEST *request, short *response_code) {
  // URL-decoding is done before everything else, so we don't need to update the string lengths etc. later
  ws_urldecode(request->filepath);

  // define auxiliary variables to make the code more human-readable
  size_t serve_dir_len = strlen(args->serve_dir), filepath_len = strlen(request->filepath);
  bool auto_index = false;

  // if the requested path hasn't got file specified, show the index file to the client
  if((request->filepath)[filepath_len - 1] == '/') {
    request->filepath = realloc(request->filepath, strlen(args->dir_index) + filepath_len + 1);
    strcpy(request->filepath + filepath_len, args->dir_index);
    filepath_len = strlen(request->filepath); // we need to update this too
    auto_index = true; // used for setting the response code, when the directory index file isn't found
  }

  // prepend the serve directory path to the requested path
  request->filepath = realloc(request->filepath, serve_dir_len + filepath_len + 1);
  request->filepath[serve_dir_len + filepath_len] = '\0';
  memmove(request->filepath + serve_dir_len, request->filepath, filepath_len);
  memcpy(request->filepath, args->serve_dir, serve_dir_len);

  // pre-check for any characters, that could make directory traversal possible
  if(strstr(request->filepath, "./") != NULL || strstr(request->filepath, "//") != NULL || strstr(request->filepath, "..") != NULL || strstr(request->filepath, "\\\\") != NULL || strstr(request->filepath, ".\\") != NULL) {
    *response_code = 403;
    return false;
  }

  // resolve to the real path for security purposes
  char buf[PATH_MAX];
  char *path = realpath(request->filepath, buf);

  // check the directory traversal again, now with the full path resolved
  // it shouldn't be possible due to the previous check on Unix-like OSes, but it could be possible on some other platforms
  if(strncmp(args->serve_dir, buf, strlen(args->serve_dir))) {
    *response_code = 403;
    return false;
  }

  // if there was a problem with the path resolving, tell the client
  if(path == NULL) {
    switch(errno) {
      case EACCES: *response_code = 403; break;
      case ENAMETOOLONG: *response_code = 414; break;
      case ENOENT: case ENOTDIR: *response_code = auto_index ? 403 : 404; break;
      default: *response_code = 500; break;
    }
    return false;
  }

  // get the stat data of a file and fail if the file cannot be stat()ed
  if(lstat(request->filepath, &request->file_stat) < 0) *response_code = 403;

  // if there is no failure so far and the "file" (Unix definiton of "file" is meant there) is not a regular fil
  char *redir_path = NULL;
  if(*response_code == 200 && !S_ISREG(request->file_stat.st_mode)) {
    if(S_ISDIR(request->file_stat.st_mode)) {
      // if the "file" is a directory, prepare redirect
      char *temp_part = buf, *last_part;
      while((temp_part = strchr(temp_part, '/')) != NULL) last_part = ++temp_part; // find the last part of the filepath (e.g. /files/images/somefolder => somefolder)

      redir_path = malloc(strlen(last_part) * 3 + 1);
      ws_urlencode(redir_path, last_part);
      size_t part_len = strlen(redir_path);

      redir_path[part_len++] = '/'; // put a trailing slash character after the folder name (e.g. somefolder => somefolder/; now the relative redirect path is prepared)
      redir_path[part_len] = '\0';

      *response_code = 302; // tell the further subroutines that the client should be redirected
    } else {
      // if it's not, fail
      *response_code = 403;
    }
  }

  // change the value of filepath to the full path, that can be fopen()ed and stat()ed later
  request->filepath = realloc(request->filepath, strlen(redir_path != NULL ? redir_path : buf) + 1);
  strcpy(request->filepath, redir_path != NULL ? redir_path : buf);

  if(redir_path != NULL) free(redir_path);

  return true;
}

void ws_client_init(WS_THREAD_ARGS *args) {
  // the default response is OK, we'll change it to something else if something bad happens
  short response_code = 200;

  // the recieved data from the client itself
  char *request_str = malloc(WS_REQUEST_MAXLEN + 1);

  // initialize the struct for saving the HTTP request properties
  // ~ method and http_ver will be pointers to a null-terminated parts of request_str
  // ~ filepath will be calloc()ed in ws_parse_request(), if nothing else fails before it
  // ~ file_stat will be filled with the stat() function in ws_resolve_filepath(), if nothing else fails before it (and is not populated with any implicit value now)
  WS_REQUEST request = {NULL, NULL, NULL};

  // get the request properties
  // every function in this "snake" returns bool and if anything ends with an error, false will be returned and the following functions won't be called (it's unneccesary and unsafe)
  (ws_recv_request(args->client_sockfd, request_str, &response_code) && ws_parse_request(&request, request_str, &response_code) && ws_validate_request(&request, &response_code) && ws_resolve_filepath(args, &request, &response_code));

  // however, we want to send the reply everytime (even a errorneous one)
  ws_send_response(args, &request, response_code);

  // Who likes memory leaks, right? :-)
  if(request.filepath != NULL) free(request.filepath);
  free(request_str);
}










/********************************
 *   ~~~   MAIN SECTION   ~~~   *
 ********************************/

// this is the first function to be called in a new thread
void *ws_handle_client(void *params) {
  ws_client_init((WS_THREAD_ARGS *) params);
  free(params);
  return NULL;
}

void ws_accept_connections(const int server_sockfd, struct sockaddr_in6 *addr, const char *serve_dir, const char *dir_index) {
  socklen_t addrlen = (socklen_t) sizeof(struct sockaddr_in6);
  pthread_t thread;

  // infinite loop serving clients
  while(true) {
    // copy the arguments to a struct, so they can be passed to thread
    WS_THREAD_ARGS *args = calloc(1, sizeof(WS_THREAD_ARGS));
    if(args == NULL) ws_crashprintf(false, "Couldn't allocate memory!");
    args->serve_dir = serve_dir;
    args->dir_index = dir_index;
    args->client_sockfd = accept(server_sockfd, (struct sockaddr *) addr, &addrlen);

    // set timeout to client's socket (if it cannot be set, the client wouldn't get served, because some error happened)
    if(setsockopt(args->client_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const void *) &CLIENT_TIMEOUT, (socklen_t) sizeof(struct timeval)) >= 0 || setsockopt(args->client_sockfd, SOL_SOCKET, SO_SNDTIMEO, (const void *) &CLIENT_TIMEOUT, (socklen_t) sizeof(struct timeval)) >= 0) {
      // create & run the thread that will serve the client
      if(pthread_create(&thread, NULL, &ws_handle_client, (void*) args) || pthread_detach(thread)) ws_crashprintf(true, "A thread to serve a client couldn't be created!");
    }
  }
}

int main(int argc, const char **argv) {
  // ### ARGUMENT VALIDATION & CONVERSION ###
  if(argc != 5) {
    ws_usage();
    ws_crashprintf(false, "Invalid number of arguments! (%d)", argc - 1);
  }

  char serve_dir[PATH_MAX];
  struct stat serve_dir_stat;
  if(realpath(argv[3], serve_dir) == NULL || lstat(serve_dir, &serve_dir_stat) < 0 || !S_ISDIR(serve_dir_stat.st_mode)) ws_crashprintf(false, "Invalid serve dir path! (%s)", argv[3]);

  if(strchr(argv[4], '/') != NULL || strchr(argv[4], '\\') != NULL || strlen(argv[4]) >= PATH_MAX) ws_crashprintf(false, "Invalid directory index filename! (%s)", argv[4]);

  // ### CONFIGURE LISTENING SOCKET ###
  struct sockaddr_in6 addr;
  ws_prepare_addr(&addr, argv[1], argv[2]);
  int server_sockfd = ws_configure_sock(&addr);

  // ### MAIN JOB ###
  ws_accept_connections(server_sockfd, &addr, serve_dir, argv[4]);

  // ### EXIT ###
  return EXIT_SUCCESS;
}
