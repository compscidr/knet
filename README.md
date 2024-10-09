# knet
[![JVM Tests](https://github.com/compscidr/knet/actions/workflows/test.yml/badge.svg)](https://github.com/compscidr/knet/actions/workflows/test.yml)&nbsp;
[![codecov](https://codecov.io/gh/compscidr/knet/graph/badge.svg?token=yBstrWw9Mm)](https://codecov.io/gh/compscidr/knet)&nbsp;

Kotlin user-space network stack. This can be used for:
- An android VPN client / server
- A kotlin / java TUN/TAP device
- Interop testing with other network protocol implementations

## What is implemented
- [x] IPv4:
  - [x] RFC 791: https://datatracker.ietf.org/doc/html/rfc791
  - [ ] RFC 4632: https://datatracker.ietf.org/doc/html/rfc4632
  - [ ] RFC 6864: https://datatracker.ietf.org/doc/html/rfc6864
  - [ ] RFC 1349 https://datatracker.ietf.org/doc/html/rfc1349
  - [ ] RFC 2474: https://datatracker.ietf.org/doc/html/rfc2474
- [x] IPv6:
  - [X] WiP: RFC 8200: https://datatracker.ietf.org/doc/html/rfc8200
  - [X] RFC 6564: https://www.rfc-editor.org/rfc/rfc6564
  - [ ] RFC 7045: https://www.rfc-editor.org/rfc/rfc7045.html
  - [ ] RFC: 4302: https://datatracker.ietf.org/doc/html/rfc4302
  - [ ] RFC: 4303: https://datatracker.ietf.org/doc/html/rfc4303
- [x] ICMP (via https://github.com/compscidr/icmp)
- [ ] TCP
- [ ] UDP
