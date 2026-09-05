# Problem Statement 26156 — what is actually being asked

Smart India Hackathon 2026 · National Technical Research Organisation ·
theme **Blockchain & Cybersecurity** · category Software.

This document is our reading of the problem statement: what each clause
demands, how a reviewer could check it, and where the wording leaves room for
interpretation. It is deliberately separate from [README.md](../README.md),
which says what we built. This one says what we were asked for, so the two can
be held against each other.

Where we quote the statement, the words are exact. Everything else is our
interpretation and is marked as such.

---

## 1. Who is asking, and why that shapes the answer

**NTRO** is India's technical intelligence agency. The contact addresses on the
statement — `nciipc.gov.in`, `helpdesk1@nciipc.gov.in` — belong to **NCIIPC**,
the National Critical Information Infrastructure Protection Centre, which sits
under NTRO and is the nodal agency for protecting critical information
infrastructure: power, banking, telecom, transport, defence.

That is not trivia. It explains three things that would otherwise look like
over-engineering:

- **Air-gapped deployment is requirement (j), not a nice-to-have.** Networks
  like these are frequently isolated by policy. A tool that phones home, pulls
  a font from a CDN, or needs a cloud API is simply not deployable.
- **Forensic preservation is stated twice** — in the description and again as
  requirement (a). Logs from critical infrastructure become evidence in
  investigations and, potentially, in court.
- **The evaluator is an operator, not a startup.** They will ask what happens
  when it breaks, what happens at scale, and what they are trusting.

## 2. The sentence that decides everything

The Background paragraph is expansive. It lists network devices, servers,
operating systems, applications, databases, cloud services, containers,
endpoint security tools, identity and access management systems, IoT devices,
"and other hardware and software platforms".

Then **Current Scope** narrows it, and this is the single most important
sentence in the statement:

> Build a framework that converts any **perimeter network device**-generated
> log or event—regardless of source, format, vendor, or technology into a
> standardized, lossless, analytics-ready representation for next-generation
> SIEM and cybersecurity platforms.

**Our reading.** The *architecture* must be general enough for anything — that
is what "universal" and "extensible" mean, and the Background is describing the
problem space, not the deliverable. The *demonstration* is scoped to perimeter
network devices: firewalls, IDS/IPS, proxies, WAFs, VPN concentrators, and the
edge services sitting behind them.

**Why this matters in practice.** Breadth is cheap to claim and expensive to
prove. A submission with forty half-working packs spanning IoT and Kubernetes
reads worse than one with eighteen perimeter packs measured against real
traffic, because the second one is what was asked for. Effort spent outside the
perimeter is effort not spent on evidence inside it.

**How our own coverage maps onto it.** Of the eighteen Source Packs we ship,
fifteen are perimeter or edge devices — firewalls and VPN (Check Point, Cisco
ASA, FortiGate, Juniper SRX, PAN-OS, iptables), network IDS (Snort, Suricata,
Enterasys Dragon), WAF (ModSecurity), proxies (Squid, Proxifier), the edge web
server (Apache access and error), and a generic CEF fallback for perimeter
appliances we have no specific pack for. Three are host or service sources
rather than perimeter devices: `linux-syslog-host`, `openssh-auth` and
`sendmail-mta`. We keep those deliberately — they demonstrate that the
framework is not perimeter-*only*, which is what "universal" in the title
requires — but they are outside the Current Scope sentence and we do not count
them as answering it.

## 3. The demand, in one paragraph

Ingest logs from any perimeter device in any format. Keep the original bytes
exactly. Parse out the fields that matter. Map them onto one common schema so
that a firewall, an IDS and a proxy describe the same event the same way. Keep
a link from every normalized record back to the original. Make adding a new
device something an operator does without writing code. Show it all in one
place, push it into a SIEM or a data lake, and make it fit to train a model on.
Do all of that inside an air-gapped network, at a scale measured in billions of
events per day.

## 4. The eleven requirements, read closely

Modal verbs in the statement are not decorative. (j) says the solution
**shall** be deployable air-gapped — mandatory. (k) says it **may** be packaged
in a container — optional, and therefore a differentiator rather than a
baseline.

### (a) Preserve complete raw event data without information loss

**The words matter.** Not "keep a copy" — *complete*, and *without information
loss*. A parser that stores the fields it understood and discards the rest has
already failed this, even if it never drops a whole record.

**A reviewer could check:** produce the exact original bytes for an arbitrary
event, including one the parser did not understand, and byte-compare.

**A weak answer:** storing a re-serialized JSON of what was parsed, and calling
it the original.

### (b) Extract and parse source-specific attributes

Per-source extraction, because a Cisco ASA line and a Snort alert have nothing
structural in common. This is the conventional parsing work; the statement
takes it as given.

**A reviewer could check:** field-level accuracy against known input, not just
"it produced output".

### (c) Normalize fields into a common event taxonomy

**"Common event taxonomy"** implies an existing, documented vocabulary rather
than one invented for the submission. A bespoke schema satisfies the letter and
fails the intent: the point is that a SIEM already understands it.

**A weak answer:** a home-grown schema with a mapping table nobody else
implements.

### (d) Maintain traceability between normalized and original events

Given (a) already requires preservation, (d) is asking for something more: a
*link*. From a normalized event you must be able to reach the original, and be
able to show that the two correspond — otherwise the link is an assertion, not
traceability.

**A reviewer could check:** take one normalized event, retrieve its original,
and confirm the correspondence is verifiable rather than merely recorded.

### (e) Plug-and-play onboarding of new log sources

**"Plug-and-play"** rules out editing source and recompiling. Onboarding must
be configuration, not development.

**A reviewer could check:** add a device the system has never seen, during the
demo, without a rebuild.

### (f) Unified visibility across enterprise environments

One place to see everything, across sources. Note this is about *unification* —
several devices visible together and comparable — not dashboard quantity.

### (g) Efficient SIEM and Data Lake integration

Two distinct destinations. SIEM implies streaming into something like Splunk,
QRadar or OpenSearch. Data lake implies durable columnar storage that Spark,
DuckDB or Athena can query. **"Efficient"** implies batching rather than a
request per event.

### (h) AI/ML-ready security and operational analytics

**"AI/ML-ready" is stronger than "structured".** A model needs a *stable* set
of columns with consistent types and an honest representation of missing
values. If the shape of the data changes whenever a parser changes, a model
trained last month is reading something different this month.

**A weak answer:** "we output JSON, and JSON is machine-readable."

### (i) Reduced parser development effort

A *comparative* claim, and the only requirement phrased as a reduction. It
therefore needs a baseline: reduced compared to what, and by how much.

**A weak answer:** asserting it is easier without ever showing the alternative.

### (j) Deployable in an air-gapped network — **shall**

Zero runtime network dependency. Not "works offline once cached" — no external
call on any path that matters. This includes the things people forget: web
fonts, CDN-hosted JavaScript, telemetry, licence checks, update pings, and
cloud model APIs.

**A reviewer could check:** pull the network cable and keep using it.

### (k) Packaged in a container — **may**

Optional. Platform independence is the stated purpose, so the image should be
self-contained and not assume host-installed dependencies.

## 5. The non-functional demands

From the Detailed Description, these are requirements too, and they are easy to
skim past:

| Word | What it demands |
|---|---|
| **Scalable** | Throughput grows with resources. A single-process design with no horizontal story fails this regardless of its benchmark. |
| **Extensible** | New sources and new fields without changing the core. Overlaps (e), but also covers the schema itself. |
| **Vendor-agnostic** | No dependence on one vendor's format, product or licence — including for the schema. |
| **Billions of events per day** | One billion per day is **11,574 events/second**, sustained. |

**On the throughput number.** The statement says the framework must be
"suitable for deployment in Big Data environments handling billions of events
per day". Our reading is that this is a claim about the *architecture* — it
must not contain a design that forbids that scale — rather than a demand that
one laptop do it. The honest position is to state measured single-node
throughput and the path to the target, and to resist quoting a number measured
at the point where records start dropping.

## 6. The theme is part of the question

The statement is filed under **Blockchain & Cybersecurity**. Nothing in
requirements (a)–(k) mentions blockchain, and inventing a cryptocurrency here
would be absurd. But the theme is a signal about what NTRO expects to see, and
the honest bridge between "blockchain" and "log preprocessing" is the part of
distributed-ledger technology that actually applies:

- append-only structures that cannot be silently rewritten,
- cryptographic hash chaining between records,
- signed commitments to state at a point in time,
- Merkle trees, which are what let you prove one record belongs to a set
  without revealing the set.

That last one is the strongest fit. Requirement (d) asks for traceability;
Merkle inclusion proofs let you *prove* it to a third party who is not
permitted to see the rest of the log — which, for a classified source, is the
difference between evidence that can be shared and evidence that cannot.

**Our reading:** treat the theme as asking for verifiable integrity, not for a
distributed ledger. A submission under this theme with no integrity story is
answering a different question than the one filed.

## 7. What is *not* asked

Worth stating, because scope creep costs more than it earns:

- **Not a SIEM.** The statement says "for next-generation SIEM and
  cybersecurity platforms" — ULPF feeds them. Alerting, case management,
  dashboards for analysts, and threat intel enrichment are the SIEM's job.
- **Not a log shipper.** Nothing asks for an agent fleet or a transport
  protocol. Receiving syslog is enough.
- **Not storage at retention scale.** Preservation is required; being the
  system of record for seven years is not.
- **Not detection content.** No rules, no signatures, no ML models. (h) asks
  for data a model can be trained on — not for the model.
- **Not a distributed ledger**, despite the theme. See section 6.

## 8. Ambiguities, and how we resolved them

Recording these so a reviewer can disagree with the reading rather than guess
at it.

| Ambiguity | Our resolution |
|---|---|
| Background lists every source type; Current Scope says perimeter network devices. | Architecture general, demonstration perimeter-focused. Section 2. |
| "Common event taxonomy" — whose? | OCSF 1.9.0. Open, vendor-neutral, and already consumed by major platforms. A bespoke schema would satisfy the words and miss the point. |
| "Billions of events per day" — per node, or per deployment? | Per deployment. We report measured single-node throughput and state the gap plainly. |
| "AI/ML-ready" — how ready? | A stable, versioned column contract with explicit missing-value handling. Not feature engineering, which belongs to whoever trains the model. |
| No dataset is provided. | Source public capture corpora ourselves and measure against them. See section 9. |
| "Reduced parser development effort" — against what baseline? | Hand-written parser code, the alternative the Background describes. |

## 9. There is no dataset

The **Dataset Link** field on the statement is empty.

That is a quiet but significant detail. Every team must find its own data, and
the easy path is to generate synthetic logs that match the parser you already
wrote — which proves nothing, because you wrote both sides. Real capture data
is messy in ways nobody anticipates, and it is the only thing that can
distinguish a framework that works from one that works on its author's
examples.

**Our position:** synthetic traffic is legitimate for demonstrating throughput
and for driving a live demo, and illegitimate as evidence of coverage. Coverage
figures come from public corpora only.

## 10. Deliverables, and their limits

| Deliverable | Limit | Notes |
|---|---|---|
| Source code link | — | GitHub or Drive. |
| Readme with setup instructions | — | Judged by whether someone can actually follow it. |
| Architecture document | **max 2 pages** | A hard cap. Over-length may not be read. |
| Demo video | **max 2 minutes** | ≈300 spoken words. Roughly six shots. |
| Technical presentation | **max 5 slides** | Five. Not five plus an appendix. |

The three capped items are the ones teams overrun. They are also the ones a
judge sees first — and in a hackathon with hundreds of submissions, the video
and the deck may be *all* that is seen before the shortlist is drawn.

## 11. How we expect this to be judged

Inference, not stated in the problem statement:

1. **Does it run?** A reviewer with the README and a laptop should reach a
   working system. Most submissions fail here.
2. **Is any of it measured?** Claims with numbers behind them beat adjectives.
3. **Is the scope honest?** Stated limitations read as competence. Discovered
   ones read as either ignorance or concealment, and a reviewer cannot tell
   which.
4. **Would it survive contact with a real network?** Non-ASCII bytes, truncated
   datagrams, a vendor who changed a field, a device nobody documented.
5. **Does it fit the theme?** Section 6.

---

## Appendix — the statement, verbatim

Preserved so this document can be checked against the source, and so a later
edit upstream is visible as a difference.

> **Problem Statement ID:** 26156
> **Title:** Universal Log Pre-processing Framework
> **Organization:** National Technical Research Organisation (NTRO)
> **Department:** National Technical Research Organisation (NTRO)
> **Category:** Software · **Theme:** Blockchain & Cybersecurity
> **Youtube Link:** Check nciipc.gov.in , helpdesk1@nciipc.gov.in
> **Dataset Link:** *(empty)*

### Background

> Modern enterprises generate massive volumes of logs from a wide range of
> sources, including network devices, servers, operating systems, applications,
> databases, cloud services, containers, endpoint security tools, identity and
> access management systems, IoT devices, and other hardware and software
> platforms. These logs are produced in diverse formats such as Syslog, JSON,
> XML, CSV, CEF, LEEF, proprietary vendor formats, and application-specific
> schemas.
>
> The diversity of log structures creates significant challenges in centralized
> monitoring, security operations, compliance reporting, incident
> investigation, and threat analytics. Security teams often spend substantial
> effort developing source-specific parsers and normalization rules before the
> data can be effectively utilized by SIEM, data lake, or machine learning
> platforms.
>
> As organizations adopt hybrid, multi-cloud, and AI-driven environments, the
> need for a universal and extensible log standard that can accommodate both
> current and future data sources have become increasingly critical.

### Detailed Description

> Design and develop a Universal Log Pre-processing Framework (ULPF) capable of
> ingesting, parsing, normalizing, and standardizing logs and events generated
> by any hardware or software system.
>
> The framework should support diverse event sources while preserving the
> original event data for forensic and compliance purposes. It should transform
> heterogeneous logs into a unified schema that enables consistent analytics,
> correlation, visualization, threat hunting, anomaly detection, and machine
> learning applications.
>
> The framework must be scalable, extensible, vendor-agnostic, and suitable for
> deployment in Big Data environments handling billions of events per day.

### Expected Solutions

> This solution should cover universal event schema and processing framework
> that enables:
>
> a) Preserve complete raw event data without information loss.
> b) Extract and parse source-specific attributes.
> c) Normalize fields into a common event taxonomy.
> d) Maintain traceability between normalized and original events.
> e) Plug-and-play on boarding of new log sources.
> f) Unified visibility across enterprise environments.
> g) Efficient SIEM and Data Lake integration.
> h) AI/ML-ready security and operational analytics.
> i) Reduced parser development effort.
> j) The solution shall be deployable in an air-gapped network.
> k) Solution may be packaged in a container for making it platform
> independent.

### Current Scope

> Build a framework that converts any perimeter network device-generated log or
> event—regardless of source, format, vendor, or technology into a
> standardized, lossless, analytics-ready representation for next-generation
> SIEM and cybersecurity platforms.

### Expected Solution/Deliverables for Evaluation

> - Source Code Link (GitHub/Drive Link)
> - Readme with Setup Instructions
> - Architecture Document (Max 2 Pages)
> - Demo Video (Max 2 Minutes)
> - Technical Presentation (Max 5 Slides)

---

*Our answer to this statement, requirement by requirement with evidence, is the
requirement table in [README.md](../README.md). What remains unfinished is in
[COMPLETION_PLAN.md](COMPLETION_PLAN.md).*
