import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getSessionUser } from "@/lib/auth";
import { sanitizeCsvCell } from "@/lib/validators";

/**
 * GET /api/reports/export-csv
 * Exports user scan history in CSV format with strict CSV Formula Injection mitigation (BK-07)
 */
export async function GET(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const scans = await prisma.scan.findMany({
      where: {
        userId: session.userId, // Mandatory data isolation (BK-05)
      },
      orderBy: { createdAt: "desc" },
      include: {
        _count: {
          select: { findings: true },
        },
      },
    });

    // CSV Headers
    const headers = [
      "ID Escaneo",
      "Host",
      "URL Objetivo",
      "Direccion IP",
      "Score de Riesgo",
      "Estado",
      "Tiempo de Respuesta (ms)",
      "Redireccion HTTPS",
      "SSL Valido",
      "Emisor SSL",
      "Dias Restantes SSL",
      "Protocolo TLS",
      "Total de Hallazgos",
      "Fecha de Escaneo",
    ];

    const rows = scans.map((s) => [
      sanitizeCsvCell(s.id),
      sanitizeCsvCell(s.host),
      sanitizeCsvCell(s.targetUrl),
      sanitizeCsvCell(s.ipAddress ?? "N/A"),
      sanitizeCsvCell(s.riskScore),
      sanitizeCsvCell(s.status),
      sanitizeCsvCell(s.responseTimeMs ?? "N/A"),
      sanitizeCsvCell(s.httpsRedirect ? "Si" : "No"),
      sanitizeCsvCell(s.sslValid ? "Si" : "No"),
      sanitizeCsvCell(s.sslIssuer ?? "N/A"),
      sanitizeCsvCell(s.sslDaysLeft ?? "N/A"),
      sanitizeCsvCell(s.sslProtocol ?? "N/A"),
      sanitizeCsvCell(s._count.findings),
      sanitizeCsvCell(s.createdAt.toISOString()),
    ]);

    const csvContent = [
      headers.join(","),
      ...rows.map((row) => row.join(",")),
    ].join("\r\n");

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
    return NextResponse.json(
      { error: "Error al exportar los datos en formato CSV" },
      { status: 500 }
    );
  }
}
