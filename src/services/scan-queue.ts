import { prisma } from "@/lib/db";
import { runScan, type RunScanOptions } from "./scanner";

const MAX_ACTIVE_SCANS_PER_INSTANCE = 2;
const MAX_PENDING_SCANS = 100;
const POLL_INTERVAL_MS = 1_000;
const STALE_JOB_MS = 2 * 60_000;
const QUEUE_CAPACITY_LOCK_ID = 17290341;

type ClaimedScan = RunScanOptions;

let activeScans = 0;
let workerStarted = false;
let polling = false;
let lastRecoveryAt = 0;

export async function enqueueScan(scan: RunScanOptions): Promise<boolean> {
  return prisma.$transaction(async (transaction) => {
    await transaction.$queryRaw`
      SELECT 1
      FROM (SELECT pg_advisory_xact_lock(${QUEUE_CAPACITY_LOCK_ID})) AS lock_result
    `;

    const pendingCount = await transaction.scanJob.count({
      where: { status: "PENDING" },
    });
    if (pendingCount >= MAX_PENDING_SCANS) return false;

    await transaction.scanJob.create({
      data: { scanId: scan.scanId },
    });
    return true;
  });
}

async function recoverAbandonedJobs(): Promise<void> {
  const now = Date.now();
  if (now - lastRecoveryAt < POLL_INTERVAL_MS * 30) return;
  lastRecoveryAt = now;

  const staleBefore = new Date(now - STALE_JOB_MS);
  const staleJobs = await prisma.scanJob.findMany({
    where: { status: "RUNNING", lockedAt: { lt: staleBefore } },
    select: { scanId: true },
  });

  for (const { scanId } of staleJobs) {
    await prisma.$transaction(async (transaction) => {
      const released = await transaction.scanJob.updateMany({
        where: { scanId, status: "RUNNING", lockedAt: { lt: staleBefore } },
        data: { status: "PENDING", lockedAt: null },
      });
      if (released.count === 0) return;

      const scan = await transaction.scan.findUnique({
        where: { id: scanId },
        select: { status: true },
      });
      if (scan?.status === "COMPLETED" || scan?.status === "FAILED") {
        await transaction.scanJob.deleteMany({ where: { scanId } });
        return;
      }

      await transaction.scan.updateMany({
        where: { id: scanId, status: { in: ["PENDING", "RUNNING"] } },
        data: { status: "PENDING", completedAt: null },
      });
    });
  }

  const recoveredCount = await prisma.$transaction(async (transaction) => {
    await transaction.$queryRaw`
      SELECT 1
      FROM (SELECT pg_advisory_xact_lock(${QUEUE_CAPACITY_LOCK_ID})) AS lock_result
    `;

    const pendingCount = await transaction.scanJob.count({
      where: { status: "PENDING" },
    });
    const availableSlots = MAX_PENDING_SCANS - pendingCount;
    if (availableSlots <= 0) return 0;

    const orphanedScans = await transaction.scan.findMany({
      where: {
        status: "PENDING",
        createdAt: { lt: staleBefore },
        scanJob: null,
      },
      orderBy: { createdAt: "asc" },
      take: availableSlots,
      select: { id: true },
    });
    if (orphanedScans.length === 0) return 0;

    const result = await transaction.scanJob.createMany({
      data: orphanedScans.map(({ id }) => ({ scanId: id })),
      skipDuplicates: true,
    });
    return result.count;
  });

  if (recoveredCount > 0) {
    console.warn(`[ScanQueue] Re-queued ${recoveredCount} orphaned pending scan(s)`);
  }
}

async function claimPendingScan(): Promise<ClaimedScan | null> {
  return prisma.$transaction(async (transaction) => {
    const claimedJobs = await transaction.$queryRaw<Array<{ scanId: string }>>`
      WITH next_job AS (
        SELECT "id"
        FROM "scan_jobs"
        WHERE "status" = 'PENDING'
        ORDER BY "createdAt"
        FOR UPDATE SKIP LOCKED
        LIMIT 1
      )
      UPDATE "scan_jobs" AS jobs
      SET "status" = 'RUNNING',
          "lockedAt" = CURRENT_TIMESTAMP,
          "updatedAt" = CURRENT_TIMESTAMP
      FROM next_job
      WHERE jobs."id" = next_job."id"
      RETURNING jobs."scanId"
    `;
    const claimedJob = claimedJobs[0];
    if (!claimedJob) return null;

    const scan = await transaction.scan.findUnique({
      where: { id: claimedJob.scanId },
      select: {
        id: true,
        userId: true,
        targetUrl: true,
        confirmedOwnership: true,
        status: true,
      },
    });

    if (!scan || scan.status !== "PENDING") {
      await transaction.scanJob.deleteMany({ where: { scanId: claimedJob.scanId } });
      return null;
    }

    return {
      scanId: scan.id,
      userId: scan.userId,
      targetUrl: scan.targetUrl,
      confirmedOwnership: scan.confirmedOwnership,
    };
  });
}

async function processScan(scan: ClaimedScan): Promise<void> {
  try {
    await runScan(scan);
  } catch (error: unknown) {
    console.error(`[ScanQueue:${scan.scanId}] Scan failed`, error);
  } finally {
    try {
      await prisma.scanJob.deleteMany({ where: { scanId: scan.scanId } });
    } catch (error: unknown) {
      console.error(`[ScanQueue:${scan.scanId}] Could not remove completed job`, error);
    }
    activeScans -= 1;
    void pollQueue();
  }
}

async function pollQueue(): Promise<void> {
  if (polling || !workerStarted) return;
  polling = true;
  try {
    await recoverAbandonedJobs();
    while (activeScans < MAX_ACTIVE_SCANS_PER_INSTANCE) {
      const scan = await claimPendingScan();
      if (!scan) break;
      activeScans += 1;
      void processScan(scan);
    }
  } catch (error: unknown) {
    console.error("[ScanQueue] Could not poll persistent scan queue", error);
  } finally {
    polling = false;
  }
}

export function startScanWorker(): void {
  if (workerStarted) return;
  workerStarted = true;
  const pollTimer = setInterval(() => void pollQueue(), POLL_INTERVAL_MS);
  pollTimer.unref();
  void pollQueue();
}
