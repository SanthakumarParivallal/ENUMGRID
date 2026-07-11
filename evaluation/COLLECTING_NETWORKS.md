# Collecting more real networks (external validity)

> The single biggest open threat to ENUMGRID's evaluation is **scale**: the
> cross-environment discovery figure pools **n = 2** environments (one real
> `/24` + one synthetic testbed). Everything needed to widen it is already
> built — this runbook makes adding each new network a three-command job. What
> it *cannot* do is invent the networks: each one must be a real estate you are
> **authorised** to scan. **No fake data, no fake networks.**

## Why this matters (in one line for the write-up)

`aggregate_runs.py` reports discovery recall as **mean ± 95 % CI across
environments**, each network counting as one sample. With n = 2 the CI is wide
and includes one synthetic host. Every additional *distinct, real* network
tightens the interval and moves the claim from *"suggestive"* to *"defensible"*.
Target **3–5** diverse estates (e.g. a home LAN, an office VLAN, an IoT-dense
segment, a cloud VPC subnet) — diversity matters more than raw count.

## Authorisation checklist (do this first, every time)

Before scanning any network, confirm **all** of the following, or do not scan it:

- [ ] You **own** the network or hold **written** authorisation from its owner to
      run active discovery + service enumeration against it.
- [ ] The range is **private / in-scope** — ENUMGRID's `ScopeValidator` refuses
      loopback, link-local, multicast, broadcast, reserved, and (by default)
      public/Internet-routable space. Do not disable that guard to reach a target.
- [ ] The subnet is on your **authorised list** (see the project memory
      `authorized-networks`); if it is a new range, get it authorised **before**
      the first probe, not after.
- [ ] You will scan **unprivileged** by default (this is also ENUMGRID's headline
      condition); only elevate on hosts/nets where you are cleared to send raw
      packets.
- [ ] Any real vulnerability you find on someone else's authorised estate goes
      through **responsible disclosure** to that owner.

## Per-network procedure

For each authorised network `<CIDR>` (e.g. `192.168.1.0/24`):

```bash
# 1. Multi-run discovery vs the nmap -sn baseline (3 runs → mean ± CI per env).
#    --ground-truth is optional; without it the harness uses union-of-tools as a
#    proxy reference (an UPPER bound on recall — state that in the write-up).
python evaluation/benchmark.py <CIDR> --runs 3 \
    --json evaluation/results/benchmark_<slug>.json \
    --plot docs/screenshots/benchmark_<slug>.png

# 2. (Optional) scalability point for this network, kept INSIDE the authorised range.
python evaluation/scalability_benchmark.py <CIDR> --repeat 2 \
    --json evaluation/results/scalability_<slug>.json
```

Use a filesystem-safe `<slug>` (e.g. `192-168-1`). Keep `--runs` and the port
posture identical across networks so the pooled figure compares like with like.

## Pool everything (the external-validity figure)

Once you have two or more `benchmark_*.json` files:

```bash
python evaluation/aggregate_runs.py evaluation/results/benchmark_*.json \
    --plot docs/screenshots/pooled_recall.png \
    --json evaluation/results/pooled_recall.json
```

This macro-averages per-network recall into **mean ± 95 % CI across
environments** and redraws the bar chart. Re-run it after each new network; the
EnumGrid CI should tighten and the `nmap -sn` bar should keep its large,
environment-dependent spread.

## Honesty notes to carry into the paper

- **Say what each environment is.** A synthetic docker testbed is not a real
  network; label it as such in the pooled table (as the current n = 2 result
  does) and prefer real estates for the headline.
- **Union-as-proxy is an upper bound.** Off-testbed, a host no tool sees is
  invisible to the metric — report recall as an upper bound unless you have
  independent ground truth (e.g. a DHCP lease table you are authorised to read).
- **More networks, not more runs.** Ten runs on one `/24` does not improve
  external validity; it tightens *internal* (run-to-run) variance only. The CI
  that matters here is *across* environments.
