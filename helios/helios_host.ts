/**
 * @mccormick/helios/host — connection profile, identity probe, and
 * read-only host-level diagnostics (thermal, load, faults, log/fmd
 * messages) plus a single-session `health_check` fan-out that produces
 * a combined `audit` resource with a verdict.
 *
 * One model instance per physical Helios machine. Other helios models
 * (`zfs`, `dladm`, `zone`) reference its `host_info` resource via CEL
 * so they don't re-probe.
 */
import { z } from "npm:zod@4";
import {
  openSession,
  pfexec,
  resolveTarget,
  sshExec,
  sshExecOrThrow,
  type SshTarget,
} from "./shared/ssh.ts";

const GlobalArgs = z.object({
  sshUser: z.string().default("root").describe(
    "Default SSH user; recommended: a non-root user with Solaris RBAC " +
      "profiles for Zone Management and ZFS Storage Management plus pfexec.",
  ),
  sshPort: z.number().int().positive().optional().describe("Default SSH port"),
  sshKnownHosts: z.string().optional().describe(
    "Path to a known_hosts file. Omit to use accept-new on first connect.",
  ),
});

const SshArgsSchema = z.object({
  sshHost: z.string().describe("Target Helios host (FQDN or IP)."),
  sshUser: z.string().optional(),
  sshPort: z.number().int().positive().optional(),
  sshKnownHosts: z.string().optional(),
});

const SshArgsShape = {
  sshHost: z.string().describe("Target Helios host (FQDN or IP)."),
  sshUser: z.string().optional(),
  sshPort: z.number().int().positive().optional(),
  sshKnownHosts: z.string().optional(),
};

const HostInfoSchema = z.object({
  host: z.string(),
  hostname: z.string(),
  uname: z.string(),
  illumosBuild: z.string(),
  heliosRelease: z.string().nullable(),
  totalMemMb: z.number().int(),
  cpuCount: z.number().int(),
  rpool: z.string(),
  probedAt: z.iso.datetime(),
});

const SensorSchema = z.object({
  name: z.string(),
  kind: z.enum(["temperature", "fan"]),
  value: z.number().nullable(),
  unit: z.string(),
  status: z.string().nullable(),
  thresholdLow: z.number().nullable().optional(),
  thresholdHigh: z.number().nullable().optional(),
});

const ThermalSchema = z.object({
  sensors: z.array(SensorSchema).default([]),
  hottestTempC: z.number().nullable(),
  slowestFanRpm: z.number().nullable(),
  fastestFanRpm: z.number().nullable(),
  anyAtThreshold: z.boolean(),
  notes: z.array(z.string()).default([]),
  observedAt: z.iso.datetime(),
});

const TopProcessSchema = z.object({
  pid: z.number().int(),
  pct: z.number(),
  rss: z.string(),
  time: z.string(),
  command: z.string(),
  zone: z.string().nullable(),
});

const TopDiskSchema = z.object({
  device: z.string(),
  rPctBusy: z.number().nullable(),
  wPctBusy: z.number().nullable(),
  kbPerSec: z.number().nullable(),
});

const LoadSnapshotSchema = z.object({
  loadAvg: z.object({
    "1m": z.number().nullable(),
    "5m": z.number().nullable(),
    "15m": z.number().nullable(),
  }),
  cpuPctTotal: z.number().nullable(),
  cpuPctByCore: z.array(z.number()).default([]),
  topProcesses: z.array(TopProcessSchema).default([]),
  topDisks: z.array(TopDiskSchema).default([]),
  pageScanRate: z.number().nullable(),
  observedAt: z.iso.datetime(),
});

const ActiveFaultSchema = z.object({
  fmri: z.string(),
  severity: z.string().nullable(),
  description: z.string().nullable(),
  suspect: z.string().nullable(),
});

const EreportSchema = z.object({
  ts: z.string().nullable(),
  class: z.string(),
  count: z.number().int(),
});

const FaultStateSchema = z.object({
  activeFaults: z.array(ActiveFaultSchema).default([]),
  recentEreports: z.array(EreportSchema).default([]),
  count: z.number().int(),
  observedAt: z.iso.datetime(),
});

const KernelMessageLineSchema = z.object({
  ts: z.string().nullable(),
  source: z.enum(["syslog", "fmd"]),
  text: z.string(),
});

const KernelMessagesSchema = z.object({
  lines: z.array(KernelMessageLineSchema).default([]),
  pattern: z.string(),
  matchedCount: z.number().int(),
  observedAt: z.iso.datetime(),
});

const AuditSchema = z.object({
  thermal: z.object({
    hottestTempC: z.number().nullable(),
    fastestFanRpm: z.number().nullable(),
    anyAtThreshold: z.boolean(),
  }),
  load: z.object({
    cpuPctTotal: z.number().nullable(),
    topProcessName: z.string().nullable(),
    topProcessPct: z.number().nullable(),
    scrubInProgress: z.boolean(),
  }),
  faults: z.object({
    count: z.number().int(),
    summary: z.array(z.string()).default([]),
  }),
  recentMessages: z.object({
    matchedCount: z.number().int(),
    sample: z.array(z.string()).default([]),
  }),
  verdict: z.enum([
    "healthy",
    "workload_driven",
    "scrub_in_progress",
    "thermal_alarm",
    "fault_present",
    "unknown",
  ]),
  verdictReason: z.string(),
  observedAt: z.iso.datetime(),
});

function parseTotalMem(prtconf: string): number {
  const m = prtconf.trim().match(/^(\d+)/);
  return m ? Number(m[1]) : 0;
}

function parseCpuCount(psrinfo: string): number {
  return psrinfo.trim().split(/\r?\n/).filter((l) => l.length > 0).length;
}

function parseRpool(zpool: string): string {
  const pools = zpool.trim().split(/\r?\n/).filter(Boolean);
  return pools.find((p) => p === "rpool") ?? pools[0] ?? "rpool";
}

// `uptime` line looks like:
//   "  3:14am  up 12 day(s), 23:11,  3 users,  load average: 0.42, 0.51, 0.55"
function parseLoadAvg(
  uptime: string,
): { "1m": number | null; "5m": number | null; "15m": number | null } {
  const m = uptime.match(
    /load average[s]?:\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/i,
  );
  if (!m) return { "1m": null, "5m": null, "15m": null };
  const num = (s: string) => {
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
  };
  return { "1m": num(m[1]), "5m": num(m[2]), "15m": num(m[3]) };
}

// Parse `prtdiag -v` temperature/fan sections. The illumos output has
// section headers; rows are whitespace-separated. We grab anything that
// looks like "<name> <value> <unit>" in the relevant block.
function parsePrtdiag(out: string): z.infer<typeof SensorSchema>[] {
  const sensors: z.infer<typeof SensorSchema>[] = [];
  const lines = out.split(/\r?\n/);
  let section: "temp" | "fan" | null = null;
  for (const raw of lines) {
    const line = raw.trim();
    if (/^=*\s*System Temperatures?/i.test(line)) {
      section = "temp";
      continue;
    }
    if (/^=*\s*Fan (Speeds?|Status)/i.test(line)) {
      section = "fan";
      continue;
    }
    if (/^=*\s*[A-Z][A-Za-z ]+:?$/.test(line) && line.length > 4) {
      if (
        !/Temperature|Fan/i.test(line) && /:$|^=/.test(line)
      ) {
        section = null;
      }
    }
    if (!section) continue;
    if (
      !line || /^-+$/.test(line) || /^Location/i.test(line) ||
      /^Device/i.test(line) || /^Sensor/i.test(line)
    ) {
      continue;
    }
    const fields = line.split(/\s+/);
    const last = fields[fields.length - 1];
    const num = Number(last);
    if (Number.isFinite(num) && fields.length >= 2) {
      const name = fields.slice(0, fields.length - 1).join(" ");
      sensors.push({
        name,
        kind: section === "temp" ? "temperature" : "fan",
        value: num,
        unit: section === "temp" ? "C" : "RPM",
        status: null,
      });
    }
  }
  return sensors;
}

// kstat -p output: module:instance:name:statistic\tvalue
// Only accept stats whose final component is a plausible sensor name AND
// whose value falls in a plausible range — illumos has no canonical sensor
// kstat module on most x86 hardware, so loose substring matches (e.g.
// "fanout", "attemptFails") would otherwise pollute the snapshot.
const TEMP_STAT_RE = /^(temperature|temp_c|temp)$/i;
const FAN_STAT_RE = /^(fan|fan_rpm|fan_speed|fanspeed|rpm)$/i;
function parseKstat(out: string): z.infer<typeof SensorSchema>[] {
  const sensors: z.infer<typeof SensorSchema>[] = [];
  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const m = line.match(/^([^\s]+)\s+(\S+)\s*$/);
    if (!m) continue;
    const [, path, val] = m;
    const num = Number(val);
    if (!Number.isFinite(num)) continue;
    const stat = path.split(":").pop() ?? "";
    if (TEMP_STAT_RE.test(stat) && num > -40 && num < 150) {
      sensors.push({
        name: path,
        kind: "temperature",
        value: num,
        unit: "C",
        status: null,
      });
    } else if (FAN_STAT_RE.test(stat) && num >= 0 && num < 30000) {
      sensors.push({
        name: path,
        kind: "fan",
        value: num,
        unit: "RPM",
        status: null,
      });
    }
  }
  return sensors;
}

// ipmitool sdr type temperature/fan output:
//   "CPU Temp        | 02h | ok  |  3.1 | 30 degrees C"
//   "Fan1            | 30h | ok  | 29.1 | 6300 RPM"
function parseIpmitoolSdr(
  out: string,
  kind: "temperature" | "fan",
): z.infer<typeof SensorSchema>[] {
  const sensors: z.infer<typeof SensorSchema>[] = [];
  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const cols = line.split("|").map((c) => c.trim());
    if (cols.length < 5) continue;
    const [name, , status, , reading] = cols;
    const numMatch = reading.match(/(-?\d+(?:\.\d+)?)/);
    const value = numMatch ? Number(numMatch[1]) : null;
    const unit = kind === "temperature" ? "C" : "RPM";
    sensors.push({
      name,
      kind,
      value,
      unit,
      status: status || null,
    });
  }
  return sensors;
}

// `prstat -Z -c -n 10 1 1` output: header lines, then rows; we want
// rows formatted like:
//   "  PID USERNAME  SIZE   RSS STATE  PRI NICE      TIME  CPU PROCESS/NLWP"
// followed by data rows, then a ZONEID summary block. Use a fixed
// column parse keyed by the header.
function parsePrstat(out: string): z.infer<typeof TopProcessSchema>[] {
  const rows: z.infer<typeof TopProcessSchema>[] = [];
  for (const raw of out.split(/\r?\n/)) {
    const line = raw.replace(/^\s+/, "");
    if (!line || /^PID\b/.test(line) || /^Total:/.test(line)) continue;
    if (/^ZONEID\b/.test(line)) break;
    const cols = line.split(/\s+/);
    if (cols.length < 9) continue;
    const pid = Number(cols[0]);
    if (!Number.isFinite(pid)) continue;
    const rss = cols[3];
    const time = cols[7];
    const cpuStr = cols[8].replace(/%$/, "");
    const cpu = Number(cpuStr);
    const command = cols.slice(9).join(" ");
    rows.push({
      pid,
      pct: Number.isFinite(cpu) ? cpu : 0,
      rss,
      time,
      command,
      zone: null,
    });
  }
  return rows.slice(0, 10);
}

// `mpstat 1 3` final block has per-CPU rows; the last column is `idl`.
// cpuPct = 100 - idl.
function parseMpstat(
  out: string,
): { perCore: number[]; total: number | null } {
  const lines = out.split(/\r?\n/);
  const headers: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*CPU\b/.test(lines[i])) headers.push(i);
  }
  if (headers.length === 0) return { perCore: [], total: null };
  const start = headers[headers.length - 1] + 1;
  const perCore: number[] = [];
  for (let i = start; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) break;
    const cols = line.split(/\s+/);
    if (cols.length < 2) continue;
    const cpu = Number(cols[0]);
    if (!Number.isFinite(cpu)) break;
    const idl = Number(cols[cols.length - 1]);
    if (Number.isFinite(idl)) perCore.push(Math.max(0, 100 - idl));
  }
  if (perCore.length === 0) return { perCore: [], total: null };
  const total = perCore.reduce((a, b) => a + b, 0) / perCore.length;
  return { perCore, total };
}

// `iostat -xnz 1 3`: last block has per-device rows. Columns end with
// `%w  %b  device`. `%b` is "the percentage of time the disk is busy".
function parseIostat(out: string): z.infer<typeof TopDiskSchema>[] {
  const lines = out.split(/\r?\n/);
  const headers: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (/extended device statistics/i.test(lines[i])) headers.push(i);
  }
  if (headers.length === 0) return [];
  const start = headers[headers.length - 1] + 2;
  const disks: z.infer<typeof TopDiskSchema>[] = [];
  for (let i = start; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) break;
    const cols = line.split(/\s+/);
    if (cols.length < 11) continue;
    // r/s w/s kr/s kw/s wait actv wsvc_t asvc_t %w %b device
    const krs = Number(cols[2]);
    const kws = Number(cols[3]);
    const pctW = Number(cols[cols.length - 3]);
    const pctB = Number(cols[cols.length - 2]);
    const device = cols[cols.length - 1];
    disks.push({
      device,
      rPctBusy: Number.isFinite(pctB) ? pctB : null,
      wPctBusy: Number.isFinite(pctW) ? pctW : null,
      kbPerSec: Number.isFinite(krs) && Number.isFinite(kws) ? krs + kws : null,
    });
  }
  return disks
    .sort((a, b) => (b.rPctBusy ?? 0) - (a.rPctBusy ?? 0))
    .slice(0, 10);
}

// `vmstat 1 3` last data row's `sr` column is the page scan rate.
function parseVmstatScanRate(out: string): number | null {
  const lines = out.split(/\r?\n/);
  let headerIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/\bsr\b/.test(lines[i]) && /\bus\b/.test(lines[i])) {
      headerIdx = i;
    }
  }
  if (headerIdx < 0) return null;
  const headers = lines[headerIdx].trim().split(/\s+/);
  const srIdx = headers.indexOf("sr");
  if (srIdx < 0) return null;
  const dataRows = lines.slice(headerIdx + 1)
    .map((l) => l.trim())
    .filter(Boolean);
  if (dataRows.length === 0) return null;
  const last = dataRows[dataRows.length - 1].split(/\s+/);
  const v = Number(last[srIdx]);
  return Number.isFinite(v) ? v : null;
}

// `fmadm faulty` is human-readable and multi-section. Each fault starts
// with a TIME/EVENT-ID/MSG-ID header, then a Host block, then Suspect
// blocks. We grab fmri + a short description.
function parseFmadmFaulty(out: string): z.infer<typeof ActiveFaultSchema>[] {
  const faults: z.infer<typeof ActiveFaultSchema>[] = [];
  const fmris = new Set<string>();
  let current: z.infer<typeof ActiveFaultSchema> | null = null;
  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trim();
    const fm = line.match(
      /^(?:Fault class|Problem|Suspect)?\s*:?\s*((?:fault|defect|alert|upset|ereport)\.[\w\-./]+)/,
    );
    if (fm) {
      const fmri = fm[1];
      if (!fmris.has(fmri)) {
        current = {
          fmri,
          severity: null,
          description: null,
          suspect: null,
        };
        faults.push(current);
        fmris.add(fmri);
      }
      continue;
    }
    if (current) {
      const sev = line.match(/Severity\s*:\s*(\S+)/);
      if (sev) current.severity = sev[1];
      const desc = line.match(/^Description\s*:\s*(.+)$/);
      if (desc) current.description = desc[1];
      const sus = line.match(/^Suspect\s*:\s*(.+)$/);
      if (sus) current.suspect = sus[1];
    }
  }
  return faults;
}

// `fmdump -e` rows: `<timestamp> ereport.<class>` — we collapse by class.
function parseFmdump(out: string): z.infer<typeof EreportSchema>[] {
  const counts = new Map<string, { ts: string | null; count: number }>();
  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || /^TIME\b/.test(line)) continue;
    const m = line.match(/^(\S+\s+\S+\s+\S+)\s+(ereport\.\S+)/);
    if (!m) continue;
    const [, ts, cls] = m;
    const cur = counts.get(cls);
    if (cur) {
      cur.count += 1;
      cur.ts = ts;
    } else {
      counts.set(cls, { ts, count: 1 });
    }
  }
  const out2: z.infer<typeof EreportSchema>[] = [];
  for (const [cls, v] of counts.entries()) {
    out2.push({ ts: v.ts, class: cls, count: v.count });
  }
  return out2.sort((a, b) => b.count - a.count);
}

function summarizeFaults(
  faults: z.infer<typeof ActiveFaultSchema>[],
): string[] {
  return faults.map((f) => {
    const parts = [f.fmri];
    if (f.severity) parts.push(`severity=${f.severity}`);
    if (f.description) parts.push(f.description);
    return parts.join(" — ");
  }).slice(0, 5);
}

function tempSummary(
  sensors: z.infer<typeof SensorSchema>[],
): {
  hottestTempC: number | null;
  slowestFanRpm: number | null;
  fastestFanRpm: number | null;
  anyAtThreshold: boolean;
} {
  let hottest: number | null = null;
  let slowest: number | null = null;
  let fastest: number | null = null;
  let alarm = false;
  for (const s of sensors) {
    if (s.value === null) continue;
    if (s.kind === "temperature") {
      if (hottest === null || s.value > hottest) hottest = s.value;
    } else if (s.kind === "fan") {
      if (slowest === null || s.value < slowest) slowest = s.value;
      if (fastest === null || s.value > fastest) fastest = s.value;
    }
    if (
      s.status &&
      /(crit|warn|alarm|nr|nc|fail)/i.test(s.status) &&
      !/^ok$/i.test(s.status)
    ) {
      alarm = true;
    }
  }
  return {
    hottestTempC: hottest,
    slowestFanRpm: slowest,
    fastestFanRpm: fastest,
    anyAtThreshold: alarm,
  };
}

async function gatherThermal(
  t: SshTarget,
): Promise<z.infer<typeof ThermalSchema>> {
  const notes: string[] = [];
  const sensors: z.infer<typeof SensorSchema>[] = [];
  const prtdiag = await sshExec(t, pfexec("prtdiag -v"));
  if (prtdiag.code === 0 || prtdiag.stdout) {
    sensors.push(...parsePrtdiag(prtdiag.stdout));
  } else {
    notes.push(`prtdiag failed: ${prtdiag.stderr.slice(-160)}`);
  }
  // Match only kstat stats whose final colon-delimited component is a
  // bare sensor name — avoids capturing incidentals like ":fanout0:..."
  // or ":attemptFails" that contain the substring "fan" or "temp".
  const kstat = await sshExec(
    t,
    "kstat -p 2>/dev/null | " +
      "awk -F: 'tolower($NF) ~ /^(temperature|temp_c|temp|fan|fan_rpm|" +
      "fan_speed|fanspeed|rpm|throttle[a-z_]*)[[:space:]]/' || true",
  );
  if (kstat.code === 0) sensors.push(...parseKstat(kstat.stdout));
  const ipmiT = await sshExec(t, pfexec("ipmitool sdr type temperature"));
  if (ipmiT.code === 0) {
    sensors.push(...parseIpmitoolSdr(ipmiT.stdout, "temperature"));
  } else {
    notes.push(
      "ipmitool sdr type temperature unavailable (not installed or no BMC)",
    );
  }
  const ipmiF = await sshExec(t, pfexec("ipmitool sdr type fan"));
  if (ipmiF.code === 0) {
    sensors.push(...parseIpmitoolSdr(ipmiF.stdout, "fan"));
  } else {
    notes.push("ipmitool sdr type fan unavailable (not installed or no BMC)");
  }
  const s = tempSummary(sensors);
  return {
    sensors,
    ...s,
    notes,
    observedAt: new Date().toISOString(),
  };
}

async function gatherLoad(
  t: SshTarget,
): Promise<z.infer<typeof LoadSnapshotSchema>> {
  const uptime = await sshExec(t, "uptime");
  const loadAvg = uptime.code === 0
    ? parseLoadAvg(uptime.stdout)
    : { "1m": null, "5m": null, "15m": null };

  const prstat = await sshExec(t, "prstat -Z -c -n 10 1 1");
  const topProcesses = prstat.code === 0 ? parsePrstat(prstat.stdout) : [];

  const mpstat = await sshExec(t, "mpstat 1 3");
  const cpu = mpstat.code === 0
    ? parseMpstat(mpstat.stdout)
    : { perCore: [], total: null };

  const iostat = await sshExec(t, "iostat -xnz 1 3");
  const topDisks = iostat.code === 0 ? parseIostat(iostat.stdout) : [];

  const vmstat = await sshExec(t, "vmstat 1 3");
  const pageScanRate = vmstat.code === 0
    ? parseVmstatScanRate(vmstat.stdout)
    : null;

  return {
    loadAvg,
    cpuPctTotal: cpu.total,
    cpuPctByCore: cpu.perCore,
    topProcesses,
    topDisks,
    pageScanRate,
    observedAt: new Date().toISOString(),
  };
}

async function gatherFaults(
  t: SshTarget,
): Promise<z.infer<typeof FaultStateSchema>> {
  const faulty = await sshExec(t, pfexec("fmadm faulty"));
  const activeFaults = faulty.code === 0 || faulty.stdout
    ? parseFmadmFaulty(faulty.stdout)
    : [];
  const dump = await sshExec(t, pfexec("fmdump -e | tail -50"));
  const recentEreports = dump.code === 0 ? parseFmdump(dump.stdout) : [];
  return {
    activeFaults,
    recentEreports,
    count: activeFaults.length,
    observedAt: new Date().toISOString(),
  };
}

const DEFAULT_MESSAGE_PATTERN = "therm|temp|fan|throttl|warn|err";

async function gatherMessages(
  t: SshTarget,
  pattern: string,
  lines: number,
): Promise<z.infer<typeof KernelMessagesSchema>> {
  const collected: z.infer<typeof KernelMessageLineSchema>[] = [];

  const syslog = await sshExec(
    t,
    pfexec(`tail -n ${lines} /var/adm/messages`),
  );
  if (syslog.code === 0) {
    const re = new RegExp(pattern, "i");
    for (const raw of syslog.stdout.split(/\r?\n/)) {
      const line = raw.trimEnd();
      if (!line || !re.test(line)) continue;
      const tsMatch = line.match(/^(\w{3}\s+\d+\s+\d+:\d+:\d+)/);
      collected.push({
        ts: tsMatch ? tsMatch[1] : null,
        source: "syslog",
        text: line,
      });
    }
  }

  const fmd = await sshExec(
    t,
    pfexec(`tail -n ${lines} /var/svc/log/system-fmd:default.log`),
  );
  if (fmd.code === 0) {
    const re = new RegExp(pattern, "i");
    for (const raw of fmd.stdout.split(/\r?\n/)) {
      const line = raw.trimEnd();
      if (!line || !re.test(line)) continue;
      const tsMatch = line.match(/^\[\s*([^\]]+?)\s*\]/);
      collected.push({
        ts: tsMatch ? tsMatch[1] : null,
        source: "fmd",
        text: line,
      });
    }
  }

  return {
    lines: collected,
    pattern,
    matchedCount: collected.length,
    observedAt: new Date().toISOString(),
  };
}

async function zpoolScrubInProgress(t: SshTarget): Promise<boolean> {
  const status = await sshExec(t, "zpool status");
  if (status.code !== 0) return false;
  return /scrub in progress|resilver in progress/i.test(status.stdout);
}

function deriveVerdict(
  thermal: z.infer<typeof ThermalSchema>,
  load: z.infer<typeof LoadSnapshotSchema>,
  faults: z.infer<typeof FaultStateSchema>,
  scrub: boolean,
): { verdict: z.infer<typeof AuditSchema>["verdict"]; reason: string } {
  const parts: string[] = [];
  if (thermal.hottestTempC !== null) {
    parts.push(`hottestTempC=${thermal.hottestTempC}`);
  }
  if (thermal.fastestFanRpm !== null) {
    parts.push(`fastestFanRpm=${thermal.fastestFanRpm}`);
  }
  if (load.cpuPctTotal !== null) {
    parts.push(`cpuPctTotal=${load.cpuPctTotal.toFixed(1)}`);
  }
  const top = load.topProcesses[0];
  if (top) parts.push(`top=${top.command}@${top.pct}%`);
  parts.push(`faultCount=${faults.count}`);

  if (faults.count > 0) {
    return { verdict: "fault_present", reason: parts.join(", ") };
  }
  if (thermal.anyAtThreshold) {
    return { verdict: "thermal_alarm", reason: parts.join(", ") };
  }
  if (scrub) {
    return {
      verdict: "scrub_in_progress",
      reason: `zpool scrub or resilver active; ${parts.join(", ")}`,
    };
  }
  if (load.cpuPctTotal !== null && load.cpuPctTotal >= 70) {
    return { verdict: "workload_driven", reason: parts.join(", ") };
  }
  return {
    verdict: "healthy",
    reason:
      "no software signal explains elevated fans — likely physical/ambient; " +
      parts.join(", "),
  };
}

export const model = {
  type: "@mccormick/helios/host",
  version: "2026.05.14.4",
  globalArguments: GlobalArgs,
  resources: {
    "host_info": {
      description: "Probed identity and capacity of the Helios host",
      schema: HostInfoSchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
    "thermal": {
      description:
        "Temperature/fan sensor snapshot from prtdiag, kstat, and (when " +
        "available) ipmitool. One per `thermal` or `health_check` call.",
      schema: ThermalSchema,
      lifetime: "7d" as const,
      garbageCollection: 20,
    },
    "load_snapshot": {
      description:
        "CPU/IO/memory pressure snapshot: load averages, per-core CPU, top " +
        "processes, top disks, page scan rate. One per `load` or " +
        "`health_check` call.",
      schema: LoadSnapshotSchema,
      lifetime: "7d" as const,
      garbageCollection: 20,
    },
    "fault_state": {
      description:
        "Active faults from fmadm and recent ereports from fmdump. One per " +
        "`faults` or `health_check` call.",
      schema: FaultStateSchema,
      lifetime: "7d" as const,
      garbageCollection: 20,
    },
    "kernel_messages": {
      description:
        "Filtered lines from /var/adm/messages and the fmd service log " +
        "matching a regex pattern. One per `messages` or `health_check` call.",
      schema: KernelMessagesSchema,
      lifetime: "7d" as const,
      garbageCollection: 20,
    },
    "audit": {
      description:
        "Combined host health audit: thermal + load + faults + recent " +
        "messages, plus a verdict explaining the host's current state. " +
        "Produced by `health_check`.",
      schema: AuditSchema,
      lifetime: "7d" as const,
      garbageCollection: 20,
    },
  },
  methods: {
    lookup: {
      description:
        "Probe the Helios host for hostname, illumos build, helios release, " +
        "memory, CPU count, and root pool. One host_info resource is written.",
      arguments: SshArgsSchema,
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        context.logger.info("Probing helios host {host}", { host: t.host });

        const uname = (await sshExecOrThrow(t, "uname -a")).stdout.trim();
        const hostname = (await sshExecOrThrow(t, "hostname")).stdout.trim();
        const prtconf = (await sshExecOrThrow(t, "prtconf -m")).stdout;
        const psrinfo = (await sshExecOrThrow(t, "psrinfo")).stdout;
        const zpool = (await sshExecOrThrow(t, "zpool list -H -o name")).stdout;

        const osRelease = await sshExec(t, "cat /etc/os-release");
        const heliosRelease = osRelease.code === 0
          ? (osRelease.stdout.match(/^PRETTY_NAME="([^"]+)"/m)?.[1] ?? null)
          : null;

        const buildOut = await sshExecOrThrow(t, "uname -v");
        const illumosBuild = buildOut.stdout.trim();

        const handle = await context.writeResource("host_info", "current", {
          host: t.host,
          hostname,
          uname,
          illumosBuild,
          heliosRelease,
          totalMemMb: parseTotalMem(prtconf),
          cpuCount: parseCpuCount(psrinfo),
          rpool: parseRpool(zpool),
          probedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    thermal: {
      description:
        "Read-only thermal snapshot. Aggregates prtdiag -v, kstat fan/temp " +
        "entries, and (best-effort) ipmitool SDR. Writes one `thermal` " +
        "resource at instance `current`.",
      arguments: SshArgsSchema,
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        context.logger.info("Reading thermal sensors on {host}", {
          host: t.host,
        });
        const data = await gatherThermal(t);
        const handle = await context.writeResource("thermal", "current", data);
        return { dataHandles: [handle] };
      },
    },

    load: {
      description:
        "Read-only load snapshot: load average, per-core CPU, top processes, " +
        "top disks, page scan rate. Writes one `load_snapshot` resource at " +
        "instance `current`.",
      arguments: SshArgsSchema,
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        context.logger.info("Reading load on {host}", { host: t.host });
        const data = await gatherLoad(t);
        const handle = await context.writeResource(
          "load_snapshot",
          "current",
          data,
        );
        return { dataHandles: [handle] };
      },
    },

    faults: {
      description:
        "Read-only fault snapshot: active faults from fmadm plus the most " +
        "recent ereport classes from fmdump. Writes one `fault_state` " +
        "resource at instance `current`.",
      arguments: SshArgsSchema,
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        context.logger.info("Reading fault state on {host}", { host: t.host });
        const data = await gatherFaults(t);
        const handle = await context.writeResource(
          "fault_state",
          "current",
          data,
        );
        return { dataHandles: [handle] };
      },
    },

    messages: {
      description:
        "Filtered tail of /var/adm/messages and the fmd service log. The " +
        "`pattern` argument is a case-insensitive regex (default matches " +
        "thermal/fan/throttle/warn/err). Writes one `kernel_messages` " +
        "resource at instance `current`.",
      arguments: z.object({
        ...SshArgsShape,
        pattern: z.string().default(DEFAULT_MESSAGE_PATTERN),
        lines: z.number().int().positive().default(200),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        context.logger.info("Reading kernel messages on {host}", {
          host: t.host,
        });
        const data = await gatherMessages(t, args.pattern, args.lines);
        const handle = await context.writeResource(
          "kernel_messages",
          "current",
          data,
        );
        return { dataHandles: [handle] };
      },
    },

    health_check: {
      description:
        "Fan-out: gather thermal + load + faults + recent messages in a " +
        "single SSH session (ControlMaster), then summarise into one " +
        "`audit` resource at instance `current` with a verdict " +
        "('healthy'|'workload_driven'|'scrub_in_progress'|'thermal_alarm'|" +
        "'fault_present'|'unknown') and a reason citing the evidence. " +
        "Use the per-domain methods (thermal/load/faults/messages) when " +
        "you need the full underlying resources.",
      arguments: z.object({
        ...SshArgsShape,
        messagePattern: z.string().default(DEFAULT_MESSAGE_PATTERN),
        messageLines: z.number().int().positive().default(200),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        context.logger.info("Running health_check on {host}", {
          host: t.host,
        });
        const sess = await openSession({
          host: t.host,
          user: t.user,
          port: t.port,
          knownHosts: t.knownHosts,
        });
        try {
          const thermal = await gatherThermal(sess.target);
          const load = await gatherLoad(sess.target);
          const faults = await gatherFaults(sess.target);
          const messages = await gatherMessages(
            sess.target,
            args.messagePattern,
            args.messageLines,
          );
          const scrub = await zpoolScrubInProgress(sess.target);

          const { verdict, reason } = deriveVerdict(
            thermal,
            load,
            faults,
            scrub,
          );
          const top = load.topProcesses[0];
          const audit: z.infer<typeof AuditSchema> = {
            thermal: {
              hottestTempC: thermal.hottestTempC,
              fastestFanRpm: thermal.fastestFanRpm,
              anyAtThreshold: thermal.anyAtThreshold,
            },
            load: {
              cpuPctTotal: load.cpuPctTotal,
              topProcessName: top ? top.command : null,
              topProcessPct: top ? top.pct : null,
              scrubInProgress: scrub,
            },
            faults: {
              count: faults.count,
              summary: summarizeFaults(faults.activeFaults),
            },
            recentMessages: {
              matchedCount: messages.matchedCount,
              sample: messages.lines.slice(-10).map((l) => l.text),
            },
            verdict,
            verdictReason: reason,
            observedAt: new Date().toISOString(),
          };
          const auditHandle = await context.writeResource(
            "audit",
            "current",
            audit,
          );

          return { dataHandles: [auditHandle] };
        } finally {
          await sess.close();
        }
      },
    },
  },
};
