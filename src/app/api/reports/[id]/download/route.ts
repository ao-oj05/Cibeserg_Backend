import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth";
import { ReportService } from "@/services/report.service";

interface RouteParams {
  params: Promise<{ id: string }>;
}

/**
 * GET /api/reports/[id]/download
 * Delegates to ReportService.getDownloadableReport (BK-05 & BK-07)
 */
export async function GET(req: NextRequest, { params }: RouteParams) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id } = await params;
    const { fileName, buffer } = await ReportService.getDownloadableReport(session.userId, id);

    return new NextResponse(buffer, {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="${fileName}"`,
        "Content-Length": buffer.length.toString(),
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
      },
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Error al descargar reporte";

    if (message.startsWith("NOT_FOUND:")) {
      return NextResponse.json({ error: message.replace("NOT_FOUND:", "") }, { status: 404 });
    }
    if (message.startsWith("EXPIRED:")) {
      return NextResponse.json({ error: message.replace("EXPIRED:", "") }, { status: 410 });
    }
    if (message.startsWith("FORBIDDEN:")) {
      return NextResponse.json({ error: message.replace("FORBIDDEN:", "") }, { status: 403 });
    }

    console.error("[Reports:Download] Error:", err);
    return NextResponse.json({ error: "Error al procesar la descarga" }, { status: 500 });
  }
}
