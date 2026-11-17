import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getSessionUser } from "@/lib/auth";

interface RouteParams {
  params: Promise<{ id: string }>;
}

/**
 * GET /api/scans/[id]
 * Retrieves details and findings for a specific scan belonging to the user (BK-05)
 */
export async function GET(req: NextRequest, { params }: RouteParams) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id } = await params;

    const scan = await prisma.scan.findFirst({
      where: {
        id,
        userId: session.userId, // Strict data isolation (BK-05)
      },
      include: {
        findings: {
          orderBy: { createdAt: "asc" },
        },
      },
    });

    if (!scan) {
      return NextResponse.json(
        { error: "Escaneo no encontrado o no tiene permisos para acceder a él" },
        { status: 404 }
      );
    }

    return NextResponse.json({ data: scan });
  } catch (err: unknown) {
    console.error("[Scans:GET_ID] Error:", err);
    return NextResponse.json(
      { error: "Error al recuperar el detalle del escaneo" },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/scans/[id]
 * Deletes a scan and its associated findings
 */
export async function DELETE(req: NextRequest, { params }: RouteParams) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id } = await params;

    // Verify ownership first
    const scan = await prisma.scan.findFirst({
      where: {
        id,
        userId: session.userId,
      },
    });

    if (!scan) {
      return NextResponse.json(
        { error: "Escaneo no encontrado o no autorizado" },
        { status: 404 }
      );
    }

    // Delete scan (findings cascade automatically)
    await prisma.scan.delete({
      where: { id },
    });

    return NextResponse.json({
      message: "Escaneo y hallazgos eliminados correctamente",
    });
  } catch (err: unknown) {
    console.error("[Scans:DELETE_ID] Error:", err);
    return NextResponse.json(
      { error: "Error al eliminar el escaneo" },
      { status: 500 }
    );
  }
}
