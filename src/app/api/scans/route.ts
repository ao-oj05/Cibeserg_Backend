import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth";
import { CreateScanSchema, ScanQuerySchema } from "@/lib/validators";
import { ScanService } from "@/services/scan.service";

/**
 * GET /api/scans
 * Delegates to ScanService.listUserScans (BK-05)
 */
export async function GET(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { searchParams } = new URL(req.url);
    const queryResult = ScanQuerySchema.safeParse({
      page: searchParams.get("page") ?? undefined,
      limit: searchParams.get("limit") ?? undefined,
      host: searchParams.get("host") ?? undefined,
    });

    if (!queryResult.success) {
      return NextResponse.json(
        { error: "Parámetros de consulta inválidos" },
        { status: 400 }
      );
    }

    const result = await ScanService.listUserScans(session.userId, queryResult.data);
    return NextResponse.json(result);
  } catch (err: unknown) {
    console.error("[Scans:GET] Error:", err);
    return NextResponse.json({ error: "Error al consultar historial de escaneos" }, { status: 500 });
  }
}

/**
 * POST /api/scans
 * Delegates to ScanService.startScan (BK-01, BK-02, BK-03)
 */
export async function POST(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const ipAddress = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "127.0.0.1";

    const body = await req.json();
    const parseResult = CreateScanSchema.safeParse(body);

    if (!parseResult.success) {
      return NextResponse.json(
        {
          error: "URL objetivo inválida",
          details: parseResult.error.flatten().fieldErrors,
        },
        { status: 400 }
      );
    }

    const scan = await ScanService.startScan(
      session.userId,
      parseResult.data.targetUrl,
      ipAddress
    );

    return NextResponse.json(
      {
        message: "Escaneo completado satisfactoriamente",
        data: scan,
      },
      { status: 201 }
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Error durante la ejecución del escaneo";

    if (message.startsWith("RATE_LIMIT:")) {
      return NextResponse.json({ error: message.replace("RATE_LIMIT:", "") }, { status: 429 });
    }
    if (message.includes("SSRF") || message.includes("bloqueado")) {
      return NextResponse.json({ error: message }, { status: 403 });
    }

    console.error("[Scans:POST] Error:", err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
