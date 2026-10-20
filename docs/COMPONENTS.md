# Stage 4: configuration and local rule-set groundwork

The `throne-config` crate now builds a full JSON envelope from supplied inbounds/outbounds and mapped local SRS definitions.

**Not production ready.** Rule-set files must already exist; their format, authenticity and compatibility have not been checked. No downloader or remote update feature is implemented. The current stage function only checks a candidate with sing-box and atomically renames it into place. It **does not** preserve a previous configuration, restart the service, test actual connectivity or roll back a failed runtime activation. Do not call it against a live router configuration.

Next: signed/checksummed downloads into a bounded cache, complete backup/rollback transaction, locking, pinned sing-box version, integration tests, and OpenWrt service control.
