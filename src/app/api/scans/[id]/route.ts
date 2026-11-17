import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth";
import { ScanService } from "@/services/scan.service";

interface RouteParams {
  params: Promise<{ id: string }>;
}

/**
 * GET /api/scans/[id]
 * Delegates to ScanService.getScanDetail (BK-05)
 */
export async function GET(req: NextRequest, { params }: RouteParams) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id } = await params;
    const scan = await ScanService.getScanDetail(session.userId, id);

    return NextResponse.json({ data: scan });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Error al consultar el escaneo";
    if (message.startsWith("NOT_FOUND:")) {
      return NextResponse.json({ error: message.replace("NOT_FOUND:", "") }, { status: 404 });
    }
    console.error("[Scans:GET_ID] Error:", err);
    return NextResponse.json({ error: "Error interno al recuperar el escaneo" }, { status: 500 });
  }
}

/**
 * DELETE /api/scans/[id]
 * Delegates to ScanService.deleteScan (BK-05)
 */
export async function DELETE(req: NextRequest, { params }: RouteParams) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id } = await params;
    await ScanService.deleteScan(session.userId, id);

    return NextResponse.json({
      message: "Escaneo y hallazgos eliminados correctamente",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Error al eliminar el escaneo";
    if (message.startsWith("NOT_FOUND:")) {
      return NextResponse.json({ error: message.replace("NOT_FOUND:", "") }, { status: 404 });
    }
    console.error("[Scans:DELETE_ID] Error:", err);
    return NextResponse.json({ error: "Error interno al eliminar el escaneo" }, { status: 500 });
  }
}
