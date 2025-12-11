# Datadog 

Datadog specific context sharing PoC code. This includes:

* [A fork of dd-trace-rs](dd-trace-rs) that activates/deactives v1 and v2 custom labels using OpenTelemetry context actions, relying on a branch of Björns that extends OpenTelemetry-rust itself to add a context activation observer mechanism
* [async-web](async-web), a simple actix application instrumented with the former, that continuously pushes sample requests through itself to generate "real" traffic


