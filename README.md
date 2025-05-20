# Kobo

Small DNS redirector.

I was tired to point my main `resolv.conf` to KDC servers. `kobo` allows to specify a DNS resolver for a single application.

`kobo` hooks the libc function `getaddrinfo()` and replaces it with it's own dumb small DNS resolv function.

``` markdown
export DNS=192.168.0.16 # IP of the internal DNS
./kobo smbclient \\internal.uauth.io\
```

## Limitations
- Anything that does not use the LIBC DNS functions.
- Binaries that have a SUID (Can't use `LD_PRELOAD`)
- Possible mDNS (`.local`)
- Only handles single `A` responses.
