import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getSessionUser } from "@/lib/auth";
import { CreateReportSchema } from "@/lib/validators";
import { generateSecurityPdfReport } from "@/services/report-generator";
import crypto from "crypto";

/**
 * GET /api/reports
 * Lists all generated reports belonging to the user
 */
export async function GET(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const reports = await prisma.report.findMany({
      where: {
        userId: session.userId, // Mandatory data isolation (BK-05)
      },
      orderBy: { createdAt: "desc" },
      include: {
        scan: {
          select: {
            id: true,
            host: true,
            riskScore: true,
            targetUrl: true,
          },
        },
      },
    });

    return NextResponse.json({ data: reports });
  } catch (err: unknown) {
    console.error("[Reports:GET] Error:", err);
    return NextResponse.json(
      { error: "Error al consultar los reportes" },
      { status: 500 }
    );
  }
}

/**
 * POST /api/reports
 * Generates a new PDF report and registers it with 7-day expiration
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

    const { scanId, type } = parseResult.data;

    let scanData = null;
    if (scanId) {
      scanData = await prisma.scan.findFirst({
        where: {
          id: scanId,
          userId: session.userId, // Strictly verify ownership
        },
        include: {
          findings: true,
        },
      });

      if (!scanData) {
        return NextResponse.json(
          { error: "El escaneo especificado no existe o no pertenece al usuario" },
          { status: 404 }
        );
      }
    }

    const reportUuid = crypto.randomUUID();

    // Generate physical PDF in private storage/reports
    const { fileName, filePath } = await generateSecurityPdfReport({
      reportId: reportUuid,
      type,
      scan: scanData,
      userEmail: session.email,
    });

    // Expiration date: +7 days from now (BK-07)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Save report record in PostgreSQL
    const report = await prisma.report.create({
      data: {
        id: reportUuid,
        userId: session.userId,
        scanId: scanId || null,
        type,
        fileName,
        filePath,
        expiresAt,
      },
    });

    // Log in AuditLog
    await prisma.auditLog.create({
      data: {
        userId: session.userId,
        action: "REPORT_GENERATED",
        metadata: { reportId: report.id, type, scanId },
      },
    });

    return NextResponse.json(
      {
        message: "Reporte generado satisfactoriamente",
        data: report,
      },
      { status: 201 }
    );
  } catch (err: unknown) {
    console.error("[Reports:POST] Error:", err);
    return NextResponse.json(
      { error: "Error al generar el reporte PDF" },
      { status: 500 }
    );
  }
}
