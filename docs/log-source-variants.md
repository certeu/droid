# Log source variants

> This page documents configuration keys introduced on the `add-variants` branch.
> It is written to be copied into [droid-docs](https://github.com/certeu/droid-docs).

A Sigma log source names the *kind* of telemetry a rule needs, not where that
telemetry comes from. `windows/process_creation` usually means Sysmon
`EventCode 1`, but the same detection is just as valid over BitDefender process
events. `webserver` usually means the Azure WAF logs, but some workspaces carry
`AGWAccessLogs` instead.

A **variant** is one telemetry source serving one log source. Each variant has
its own pipeline group, produces its own query, and is deployed as its own
object on the platform.

## Declaring variants

Variants are declared by adding `variant` to the pipeline groups that serve the
same log source, and marking exactly one of them `primary`:

```toml
[platforms.splunk.pipelines.windows_process_creation]
pipelines = ["tests/files/pipelines/splunk_process_creation.yml"]
product = "windows"
category = "process_creation"
variant = "sysmon"
primary = true

[platforms.splunk.pipelines.windows_process_creation_bitdefender]
pipelines = ["tests/files/pipelines/splunk_process_creation_bitdefender.yml"]
product = "windows"
category = "process_creation"
variant = "bitdefender"
```

Rules matching `windows/process_creation` now convert twice, once through each
pipeline group.

A log source served by a single pipeline group needs no `variant` key at all —
it is implicitly the primary. **Every configuration written before variants
existed keeps working unchanged.**

### Configuration errors

Once a log source is served by more than one group, droid refuses to guess and
raises an error when:

- one of the groups has no `variant` name
- two groups declare the same `variant` name
- no group, or more than one group, claims `primary`

Before variants, two groups matching the same log source silently resolved to
whichever one the config happened to list first. That coin flip is now a loud
failure.

## Identity on the platform

The primary variant deploys under the **bare Sigma UUID and the bare rule
title** — exactly what droid did before variants existed. Nothing already
deployed moves, and no migration is needed.

Every other variant derives a stable identity from the Sigma id:

| | Sentinel / XDR `rule_id` | Splunk saved search name |
|---|---|---|
| primary | the Sigma `id` | `Suspicious process` |
| `bitdefender` | `uuid5(sigma_id, "bitdefender")` | `Suspicious process [bitdefender]` |

The derived UUID is a function of the Sigma id and the variant name only, so it
is stable across runs and unique per rule — two different rules never collide on
the same variant name.

## Platform-wide telemetry

A single-tenant deployment that only carries some of the declared sources can
narrow them once, on the platform itself:

```toml
[platforms.splunk]
variants = ["bitdefender"]
```

Only those variants are ever converted or deployed. Omit the key to get all of
them, which is the default. It narrows exactly what a per-customer list
narrows — see [below](#what-an-allowlist-does-and-does-not-narrow).

## Per-customer telemetry (MSSP)

Customers rarely carry every source. Each `export_list_mssp` entry may declare
the variants that customer actually has:

```toml
[platforms.microsoft_xdr.export_list_mssp.customer_a]
tenant_id = "..."
customer_name = "Customer A"
variants = ["defender", "thirdparty"]

[platforms.microsoft_xdr.export_list_mssp.customer_b]
tenant_id = "..."
customer_name = "Customer B"
variants = ["thirdparty"]
```

Customer B is never sent the native Defender query — it would run against data
they do not have and silently return nothing forever.

An entry **without** a `variants` key receives every variant, which is what
configurations predating this feature expect.

### What an allowlist does and does not narrow

One `variants` list covers the whole platform, so it can only narrow the log
sources that actually offer a choice. A pipeline group is subject to the
allowlists **only if it declares a `variant` name**.

Nearly every log source is served by a single group with no `variant` key.
Those rules keep deploying to everyone regardless of the allowlist — otherwise
adding `variants` to one customer, to pick their `process_creation` source,
would silently stop every other rule in the repository from reaching them.

That also gives you the escape hatch for the opposite case: to withhold a
single-source log source from a customer, give its group a `variant` name and
leave that name out of their list.

`droid rules convert --mssp` renders the same narrowing, so what you see per
customer is what will be deployed to them. Run it with `--debug` to see the
`[customer / variant]` labels.

### Orphan reporting

Removing a variant from a customer's `variants` list stops droid deploying it,
but whatever was already pushed keeps running in their tenant. When droid skips
a customer for that reason it looks the rule up and **warns** if it is still
there:

```
Orphan rule foo.yml (defender) still deployed in tenant <id> for 'Customer B',
which no longer carries that telemetry. Remove it manually if it is no longer wanted.
```

droid never deletes it. Only the operator knows whether the leftover is stale or
still wanted, and a detection deleted by surprise is worse than one reported.

Note the limit: droid can only report a variant it still knows about. Deleting a
pipeline group from the config entirely leaves droid with no name to look up, so
remove it from every customer's `variants` list first, let a run report the
leftovers, and only then drop the group.

## Splunk

Splunk has no MSSP concept — customers are scoped inside the query by the
`index` and `splunk_server` conditions the pipeline injects. A variant is
therefore **one saved search**, with every relevant customer index merged in its
pipeline. The number of saved searches is `rules × variants`, independent of how
many customers there are.

### Suppression fields

Suppression fields are named per log source, but variants have different
schemas — suppressing a Sysmon rule on `Computer` says nothing about the same
detection over BitDefender data. A variant group may declare its own:

```toml
[platforms.splunk.pipelines.windows_process_creation_bitdefender]
pipelines = ["..."]
product = "windows"
category = "process_creation"
variant = "bitdefender"
"alert.suppress.fields" = "aid,process_path"
```

This takes precedence over the log-source-wide
`savedsearch_parameters.suppress_fields_groups` entry. A variant that shares the
primary's schema simply omits the key and inherits it.

The per-rule `custom: alert.suppress.fields` override still wins over both.
