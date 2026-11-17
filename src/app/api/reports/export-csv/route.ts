import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth";
import { ReportService } from "@/services/report.service";

/**
 * GET /api/reports/export-csv
 * Delegates to ReportService.exportScansToCsv (BK-07)
 */
export async function GET(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const csvContent = await ReportService.exportScansToCsv(session.userId);

    return new NextResponse(csvContent, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="scandev-scans-${new Date().toISOString().slice(0, 10)}.csv"`,
        "Cache-Control": "no-store, private",
      },
    });
  } catch (err: unknown) {
    console.error("[Reports:ExportCSV] Error:", err);
    return NextResponse.json({ error: "Error al exportar los datos en formato CSV" }, { status: 500 });
  }
}
