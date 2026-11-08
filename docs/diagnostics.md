# Diagnostic logging

[Back to the overview](../README.md).

Pass a `diagnostic.Sink` with `options.WithDiagnosticSink` to receive one typed
event per CTAP command. The event includes command and subcommand metadata plus
redacted request and response CBOR diagnostic notation; raw wire bytes are
never passed to the sink. The sink runs synchronously after the transport
exchange, has no error return, and should return promptly.

Diagnostic notation is a normalized, pretty-printed view for troubleshooting,
not a byte-exact dump. Unknown commands and CBOR fields are preserved. Known
integer keys are annotated with CTAP field names using extended diagnostic
notation comments, for example `/clientDataHash/ 1: h'...'`. Fields tagged with
the `redact` option in `ctapdiag` are replaced with an empty value of the same
CBOR type, annotated with `[REDACTED]`, before the log record is created; for
example, a byte string becomes `h'/[REDACTED]/'`. The first tag component
overrides the displayed name; `-` keeps the name derived from the Go field, as
in `ctapdiag:"-,redact"`.

Diagnostic events are redacted, not anonymized. They may contain relying party,
user, credential, and biometric template identifiers and should be treated as
sensitive data. Unknown and vendor-defined fields have no redaction metadata,
so their normalized values are included unredacted.
