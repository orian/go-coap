# Constrained Application Protocol implementation in Go

 - Message Marshal/Unmarshal
 - Simple client and server

You can read more about CoAP in [rfc7252][coap].

Contains some preliminary work on `SUBSCRIBE` support from
[an early draft][shelby].

[shelby]: http://tools.ietf.org/html/draft-shelby-core-coap-01
[coap]: http://tools.ietf.org/html/rfc7252

### Diffs from original repo
 - merged all branches/forks which introduce any new fixes (token parsing, full standard implementation, some test)
 - fix minimum message length (according to protocol spec it's 4 bytes)
 - put all errors as constants
 - If msg had no Payload then Message.Payload is nil instead of a slice of size 0.