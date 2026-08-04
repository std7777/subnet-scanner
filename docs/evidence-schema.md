# Evidence schema

The evidence model is the neutral boundary between observation components and
the downstream risk-analysis system.

## Version

The current schema version is `1.0`.

- Backward-compatible optional fields may be added within version 1.
- Removing fields, changing meanings, or changing field types requires a new
  major version.
- Every report carries its own `schemaVersion`.

## Report envelope

`ObservationReport` records:

- a unique observation ID;
- observation mode and completion status;
- start and finish timestamps;
- the observer and its vantage point;
- the requested target;
- zero or more host-reachability observations;
- zero or more port observations;
- zero or more collection errors;
- neutral metadata describing how evidence was collected.

## Port observations

`PortObservation` can represent:

- a locally listening TCP or UDP socket;
- an open, closed, filtered, unreachable, or unknown network port;
- bind address and network interface;
- connection latency;
- owning process or container information;
- service-identification evidence;
- banners and TLS evidence;
- mode-specific attributes that are not yet first-class fields.

The observation state describes only what was seen from the report's vantage
point. For example, `LISTENING` on the local host and `OPEN` from an internal
scanner are separate facts.

## Neutrality

The model intentionally contains no risk score, severity, allow/deny decision,
or safe/unsafe label. Those decisions belong to the downstream AI system.

Service names are evidence with an identification source and confidence, not
guaranteed facts. Errors are retained so a partial scan cannot be confused with
a complete scan that found nothing.

## Compatibility

The existing `ScanReport`, `HostReport`, and `ScanResult` classes remain as an
internal compatibility layer. The command-line scanner maps them into the
versioned evidence model before serializing its JSON output.
