# EtServer
A low-memory-footprint web server for serving static content.


## Compiling
Easy as can be:
```
gcc etserver.c -o etserver -l pthread
```

Tested on:
* Debian 10 (Linux kernel 4.19.0-8 amd64, gcc 8.3.0, glibc 2.28)
* Raspbian 10 (Linux kernel 4.19.97+ armv6l, gcc 8.3.0, glibc 2.28)
* Fedora 31 (Linux kernel 5.5.16-200 amd64, gcc 9.3.1, glibc 2.30)


## Usage
Start the compiled executable with the following arguments:
1. A IPv6/v4 __listen address__ (e.g. :: or 0.0.0.0)
2. The __port number__ to listen on (e.g. 8080)
3. Path to a directory that will be used as __web root__ (= the directory to serve content from, both absolute and relative paths are allowed)
4. Directory __index filename__ (if the URL is pointed to a directory, this file will be served; e.g. index.html)

If you need to listen on a port that is in the range of privileged ports (0-1023) on Unix-like operating systems, make the server listen on a higher port number and then use your firewall to redirect the privileged port to the listening port. Otherwise, you would need to run this server as root which is not recommended!


## Licensing
This project is licensed under __MIT License__.


## Want to contribute?
If you want to remind me of any bug or fix it right away, add some new functionality or just make something better, feel free to create a pull request or an issue.
