import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth";
import { CreateReportSchema } from "@/lib/validators";
import { ReportService } from "@/services/report.service";

/**
 * GET /api/reports
 * Delegates to ReportService.listReports (BK-05)
 */
export async function GET(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const reports = await ReportService.listReports(session.userId);
    return NextResponse.json({ data: reports });
  } catch (err: unknown) {
    console.error("[Reports:GET] Error:", err);
    return NextResponse.json({ error: "Error al consultar los reportes" }, { status: 500 });
  }
}

/**
 * POST /api/reports
 * Delegates to ReportService.generateReport (BK-07)
 */
export async function POST(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const body = await req.json();
    const parseResult = CreateReportSchema.safeParse(body);

    if (!parseResult.success) {
      return NextResponse.json(
        { error: "Parámetros de reporte inválidos", details: parseResult.error.flatten().fieldErrors },
        { status: 400 }
      );
    }

    const report = await ReportService.generateReport(
      session.userId,
      session.email,
      parseResult.data
    );

    return NextResponse.json(
      {
        message: "Reporte generado satisfactoriamente",
        data: report,
      },
      { status: 201 }
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Error al generar reporte";
    if (message.startsWith("NOT_FOUND:")) {
      return NextResponse.json({ error: message.replace("NOT_FOUND:", "") }, { status: 404 });
    }
    console.error("[Reports:POST] Error:", err);
    return NextResponse.json({ error: "Error al generar el reporte PDF" }, { status: 500 });
  }
}
