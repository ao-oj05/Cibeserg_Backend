import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getSessionUser } from "@/lib/auth";
import fs from "fs";
import path from "path";

interface RouteParams {
  params: Promise<{ id: string }>;
}

/**
 * GET /api/reports/[id]/download
 * Secure download verifying ownership and expiration (+7 days) (BK-05 & BK-07)
 */
export async function GET(req: NextRequest, { params }: RouteParams) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id } = await params;

    // Verify ownership strictly by session.userId (BK-05)
    const report = await prisma.report.findFirst({
      where: {
        id,
        userId: session.userId,
      },
    });

    if (!report) {
      return NextResponse.json(
        { error: "Reporte no encontrado o no tiene autorización" },
        { status: 404 }
      );
    }

    // Check expiration window (BK-07)
    if (new Date() > new Date(report.expiresAt)) {
      return NextResponse.json(
        { error: "El enlace de descarga del reporte ha expirado (vigencia de 7 días concluida)" },
        { status: 410 }
      );
    }

    // Ensure physical file path exists and is confined within storage/reports
    const safeStorageDir = path.resolve(process.env.STORAGE_REPORTS_DIR || "./storage/reports");
    const absoluteFilePath = path.resolve(report.filePath);

    // Path traversal check
    if (!absoluteFilePath.startsWith(safeStorageDir)) {
      return NextResponse.json(
        { error: "Ruta de archivo no válida o insegura" },
        { status: 403 }
      );
    }

    if (!fs.existsSync(absoluteFilePath)) {
      return NextResponse.json(
        { error: "El archivo físico del reporte no se encuentra en el almacenamiento" },
        { status: 404 }
      );
    }

    const fileBuffer = fs.readFileSync(absoluteFilePath);

    return new NextResponse(fileBuffer, {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="${report.fileName}"`,
        "Content-Length": fileBuffer.length.toString(),
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
      },
    });
  } catch (err: unknown) {
    console.error("[Reports:Download] Error:", err);
    return NextResponse.json(
      { error: "Error al procesar la descarga del reporte" },
      { status: 500 }
    );
  }
}
