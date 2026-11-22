import { runScan, type RunScanOptions } from './scanner';

const MAX_ACTIVE_SCANS = 2;
const MAX_PENDING_SCANS = 100;

const queue: RunScanOptions[] = [];
let activeScans = 0;
let scheduled = false;

function scheduleWorker(): void {
  if (scheduled) return;
  scheduled = true;
  setImmediate(() => {
    scheduled = false;
    while (activeScans < MAX_ACTIVE_SCANS && queue.length > 0) {
      const scan = queue.shift();
      if (!scan) break;
      activeScans += 1;
      void runScan(scan)
        .catch((error: unknown) => {
          console.error(`[ScanQueue:${scan.scanId}] Scan failed`, error);
        })
        .finally(() => {
          activeScans -= 1;
          scheduleWorker();
        });
    }
  });
}

export function enqueueScan(scan: RunScanOptions): boolean {
  if (
    queue.length >= MAX_PENDING_SCANS ||
    activeScans + queue.length >= MAX_ACTIVE_SCANS + MAX_PENDING_SCANS
  ) {
    return false;
  }
  queue.push(scan);
  scheduleWorker();
  return true;
}
