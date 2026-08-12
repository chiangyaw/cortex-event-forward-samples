# Cortex XDR — Event Forwarding Log Samples

Sample events exported from a **Palo Alto Networks Cortex XDR / XSIAM** tenant via
**Event Forwarding to cloud storage**. In a live deployment, Cortex forwards
selected datasets to an object-storage bucket (here, Google Cloud Storage) as
newline-delimited JSON — **one JSON object per event**. These files are a small,
de-duplicated, **redacted** subset intended as a *format/schema reference*.

> These samples are for illustrating the **structure** of Cortex forwarded logs.
> Identifiers have been redacted (see [Redaction](#redaction)); values are not
> operationally meaningful. Not an official Palo Alto Networks artifact.

## The two datasets

| Dataset | Source | What it is |
|---|---|---|
| **`xdr_data`** | Cortex XDR **endpoint agent** (EDR telemetry) | Raw endpoint activity — process, network, file, registry, and module-load events emitted by the Cortex agent. Distinguished by integer `event_type` / `event_sub_type` codes and `agent_*` fields; **no** ingestion envelope. |
| **`cwp_packages_raw`** | Cortex **Cloud Workload Protection (CWP)** | Software / package (SBOM-style) inventory discovered on cloud workloads and container images. Carries an ingestion envelope (`_vendor=CWP`, `_product=packages`, `_bundle_id=PANW/cwp_packages/…`) and references cloud assets (`related_asset_type` = `EC2_INSTANCE` / `CORE_IMAGE`) — **not** endpoint-agent data. |

The two are easy to tell apart programmatically: `cwp_packages_raw` events have
`_vendor == "CWP"`; `xdr_data` events do not carry that envelope and instead have
integer `event_type` + `agent_id`.

## Source: cloud-storage bucket layout

Cortex writes forwarded events to the destination bucket as **date-partitioned,
newline-delimited JSON objects** (one event per line), namespaced by vendor and
product/dataset. The layout below is reconstructed from these samples — the
bucket name comes from the export manifest, and the object-key path is taken
directly from the `_bundle_id` field carried on every forwarded event:

```
gs://xdr-<region>-<TENANT_ID>-event-forwarding/     # e.g. xdr-eu-<TENANT_ID>-event-forwarding
└── PANW/                                            # vendor namespace
    ├── cwp_packages/                                # <product> — Cloud Workload Protection package inventory
    │   └── 2026-08-11/                              # <YYYY-MM-DD>  (ingestion date partition)
    │       ├── packages_<TENANT_ID>_<n>_<asset-hash>_1   # one NDJSON bundle per object
    │       └── packages_<TENANT_ID>_<n>_<asset-hash>_0   # trailing _<seq> is the bundle sequence
    └── xdr_data/                                    # endpoint EDR telemetry (same convention*)
        └── 2026-08-11/
            └── <bundle files…>
```

- **Bucket name** — `xdr-<region>-<TENANT_ID>-event-forwarding` (observed:
  `xdr-eu-2004776267262-event-forwarding`). `<region>` reflects the tenant's
  data residency (e.g. `eu`); `<TENANT_ID>` is the numeric Cortex tenant id.
- **Object key** — `PANW/<product>/<YYYY-MM-DD>/<bundle-file>`. Directly
  observed for CWP via `_bundle_id`, e.g.
  `PANW/cwp_packages/2026-08-11/packages_<TENANT_ID>_..._<asset-hash>_1`. The
  trailing `_1` / `_0` is the bundle sequence number for that partition.
- **Object contents** — NDJSON: one JSON event object per line (as reproduced by
  [`samples/`](samples/), which splits each bundle back into per-event files).
- \*`xdr_data` events do **not** carry a `_bundle_id`, so their exact object key
  is not visible in the data; the `PANW/xdr_data/<date>/…` path above follows the
  same forwarding convention and is shown for illustration, not asserted.

## Repository layout

```
samples/
├── xdr_data/            # endpoint EDR telemetry (17 unique event shapes)
└── cwp_packages_raw/    # cloud-workload package inventory (3 unique shapes)
```

## `xdr_data` — endpoint telemetry (17 samples)

One representative per unique `event_type` × `event_sub_type`. Enum labels below
were resolved against a live Cortex tenant.

| File | `event_type` | `event_sub_type` | Description |
|---|---|---|---|
| [`process_start.json`](samples/xdr_data/process_start.json) | `PROCESS` (1) | `1` → `PROCESS_START` | A process was created. Carries the acting/causality process chain, command line, image path + MD5/SHA256, signer, user, integrity/logon info. |
| [`process_stop.json`](samples/xdr_data/process_stop.json) | `PROCESS` (1) | `2` → `PROCESS_STOP` | A process terminated. |
| [`network_stream_connect.json`](samples/xdr_data/network_stream_connect.json) | `NETWORK` (2) | `3` → `NETWORK_STREAM_CONNECT` | Outbound TCP connection established — local/remote IP + port, protocol, and the initiating process. |
| [`network_stream_accept.json`](samples/xdr_data/network_stream_accept.json) | `NETWORK` (2) | `2` → `NETWORK_STREAM_ACCEPT` | Inbound TCP connection accepted by a listening process (endpoint acting as server). |
| [`network_stream_listen.json`](samples/xdr_data/network_stream_listen.json) | `NETWORK` (2) | `1` → `NETWORK_STREAM_LISTEN` | A process began listening on a socket (server bind). |
| [`network_stream_disconnect.json`](samples/xdr_data/network_stream_disconnect.json) | `NETWORK` (2) | `4` → `NETWORK_STREAM_DISCONNECT` | A TCP stream was closed (often carries byte counts / duration). |
| [`network_stream_connect_failed.json`](samples/xdr_data/network_stream_connect_failed.json) | `NETWORK` (2) | `6` → `NETWORK_STREAM_CONNECT_FAILED` | An outbound TCP connection attempt failed. |
| [`network_datagram_statistics.json`](samples/xdr_data/network_datagram_statistics.json) | `NETWORK` (2) | `11` → `NETWORK_DATAGRAM_STATISTICS` | Aggregated UDP datagram flow statistics. |
| [`network_subtype_18_reserved.json`](samples/xdr_data/network_subtype_18_reserved.json) | `NETWORK` (2) | `18` → `NETWORK_SUBTYPE_18_RESERVED` | NETWORK event with `event_sub_type=18`, which is not present in the current tenant enum (reserved / agent-version-specific). Included for schema completeness. |
| [`file_create_new.json`](samples/xdr_data/file_create_new.json) | `FILE` (3) | `1` → `FILE_CREATE_NEW` | A new file was created. |
| [`file_write.json`](samples/xdr_data/file_write.json) | `FILE` (3) | `6` → `FILE_WRITE` | An existing file was written / modified. |
| [`file_rename.json`](samples/xdr_data/file_rename.json) | `FILE` (3) | `3` → `FILE_RENAME` | A file was renamed or moved (carries the previous path & name). |
| [`file_remove.json`](samples/xdr_data/file_remove.json) | `FILE` (3) | `5` → `FILE_REMOVE` | A file was deleted. |
| [`registry_create_key.json`](samples/xdr_data/registry_create_key.json) | `REGISTRY` (4) | `1` → `REGISTRY_CREATE_KEY` | A Windows registry key was created. |
| [`registry_set_value.json`](samples/xdr_data/registry_set_value.json) | `REGISTRY` (4) | `4` → `REGISTRY_SET_VALUE` | A Windows registry value was set (key path, value name, data, value type). |
| [`registry_subtype_6_reserved.json`](samples/xdr_data/registry_subtype_6_reserved.json) | `REGISTRY` (4) | `6` → `REGISTRY_SUBTYPE_6_RESERVED` | REGISTRY event with `event_sub_type=6`, not present in the current tenant enum (reserved / version-specific). Included for completeness. |
| [`load_image_module.json`](samples/xdr_data/load_image_module.json) | `LOAD_IMAGE` (6) | `1` → `LOAD_IMAGE_MODULE` | A module / DLL image was loaded into a process (module path, hashes, signer). |

**Key fields:** `event_type`/`event_sub_type` (integer enums), `event_timestamp`
(epoch ms), `agent_id` / `agent_hostname` / `agent_os_type`, and the acting
process context (`os_actor_process_*`, `actor_process_*`, `causality_actor_*`).
Action-specific payloads use the `action_*` prefix — e.g. `action_file_*`,
`action_network_*` (`action_local_ip`, `action_remote_ip`, ports, protocol),
`action_registry_*`, `action_module_*`.

## `cwp_packages_raw` — cloud workload package inventory (3 samples)

| File | `related_asset_type` | Package type | Description |
|---|---|---|---|
| [`cwp_ec2_instance_golang_os_package.json`](samples/cwp_packages_raw/cwp_ec2_instance_golang_os_package.json) | `EC2_INSTANCE` | `pkg:golang/…` | Software-inventory item found on a **running cloud host** (AWS `EC2_INSTANCE`). An OS-level Go package extracted from an installed binary — `purl`, version, file paths, and disk/volume location. |
| [`cwp_core_image_golang.json`](samples/cwp_packages_raw/cwp_core_image_golang.json) | `CORE_IMAGE` | `pkg:golang/…` | Inventory item found inside a **container / core image** (`CORE_IMAGE`, not a running host). A Go package. |
| [`cwp_core_image_deb_package.json`](samples/cwp_packages_raw/cwp_core_image_deb_package.json) | `CORE_IMAGE` | `pkg:deb/…` | A Debian (`dpkg`/`apt`) OS package found inside a **container / core image** — `purl` = `pkg:deb/...`, with origin package metadata. |

**Key fields:** ingestion envelope (`_vendor`, `_product`, `_time`,
`_insert_time`, `_reception_time`, `_bundle_id`, `_id`); package identity
(`purl`, `name`, `version`, `type`, `origin_package_name`, `os_package`); the
cloud asset it was found on (`related_asset_type`, `related_asset_id`,
`strong_id`); and file/disk location (`path`, `full_pkg_path`, `disk_id`,
`volume_name`, `partition_type`).

## Redaction

Structure and field names are **100% intact**; only sensitive identifier
*values* were replaced with stable placeholders:

| Original | Replaced with |
|---|---|
| Tenant / cloud account id | `ACCOUNT_ID` |
| `agent_id` | `AGENT_ID_<n>` |
| `related_asset_id` | `ASSET_ID_<n>` |
| `disk_id` | `DISK_ID_<n>` |
| `volume_name` (`vol-…`) | `vol-REDACTED_<n>` |
| `partition_id` (UUID) | all-zero UUID |
| Windows account SIDs | sub-authorities zeroed → `S-1-5-21-0-0-0-<RID>` |
| User names in file paths | `\USER\` / `/home/USER/` |
| Public IPv4 addresses | `203.0.113.x` (RFC 5737 documentation range) |

Left intact (not sensitive, useful for reference): file/module MD5 & SHA-256
hashes (software hashes), package names / `purl` / maintainer metadata, ports,
RFC 1918 private IPs, built-in account names (`SYSTEM`, `LOCAL SERVICE`), and
the demonstration domain `vandelayindustries.com`.

## License

Released under [CC0 1.0 Universal](LICENSE) (public-domain dedication) — these
redacted sample shapes may be used freely, without attribution, as a
format/schema reference. Not an official Palo Alto Networks artifact; "Cortex",
"Cortex XDR", and "XSIAM" are trademarks of Palo Alto Networks.
