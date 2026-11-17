import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getSessionUser } from "@/lib/auth";
import { checkRateLimit } from "@/lib/rate-limit";
import { CreateScanSchema, ScanQuerySchema, escapeSqlLike } from "@/lib/validators";
import { executeSecurityScan } from "@/services/scanner";

/**
 * GET /api/scans
 * Returns paginated scan history for the authenticated user (BK-05)
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

    const { page, limit, host } = queryResult.data;
    const skip = (page - 1) * limit;

    const whereClause: {
      userId: string;
      host?: { contains: string; mode: "insensitive" };
    } = {
      userId: session.userId, // Mandatory data isolation (BK-05)
    };

    if (host) {
      const sanitizedHost = escapeSqlLike(host);
      whereClause.host = {
        contains: sanitizedHost,
        mode: "insensitive",
      };
    }

    const [scans, totalCount] = await Promise.all([
      prisma.scan.findMany({
        where: whereClause,
        orderBy: { createdAt: "desc" },
        skip,
        take: limit,
        select: {
          id: true,
          targetUrl: true,
          host: true,
          ipAddress: true,
          riskScore: true,
          status: true,
          responseTimeMs: true,
          httpsRedirect: true,
          sslValid: true,
          sslIssuer: true,
          sslDaysLeft: true,
          sslProtocol: true,
          startedAt: true,
          completedAt: true,
          createdAt: true,
          _count: {
            select: { findings: true },
          },
        },
      }),
      prisma.scan.count({ where: whereClause }),
    ]);

    return NextResponse.json({
      data: scans,
      meta: {
        page,
        limit,
        total: totalCount,
        totalPages: Math.ceil(totalCount / limit),
      },
    });
  } catch (err: unknown) {
    console.error("[Scans:GET] Error:", err);
    return NextResponse.json(
      { error: "Error al consultar historial de escaneos" },
      { status: 500 }
    );
  }
}

/**
 * POST /api/scans
 * Triggers a new passive cybersecurity scan
 */
export async function POST(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const ipAddress = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "127.0.0.1";

    // 1. Rate Limiting Check (BK-02)
    const rateLimit = checkRateLimit(`scan:${session.userId}`, { limit: 10, windowMs: 60_000 });
    if (!rateLimit.success) {
      return NextResponse.json(
        {
          error: "Límite de escaneos excedido. Máximo 10 escaneos por minuto.",
          resetInMs: rateLimit.resetMs,
        },
        { status: 429 }
      );
    }

    // 2. Validate Target URL with Zod (BK-03)
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

    const { targetUrl } = parseResult.data;

    // Log scan request in AuditLog
    await prisma.auditLog.create({
      data: {
        userId: session.userId,
        action: "SCAN_STARTED",
        ipAddress,
        metadata: { targetUrl },
      },
    });

    // 3. Execute Security Scan via Orchestrator (SSRF Guard + parallel checks)
    const scan = await executeSecurityScan({
      userId: session.userId,
      targetUrl,
    });

    // Log scan completed
    await prisma.auditLog.create({
      data: {
        userId: session.userId,
        action: "SCAN_COMPLETED",
        ipAddress,
        metadata: { scanId: scan.id, riskScore: scan.riskScore },
      },
    });

    return NextResponse.json(
      {
        message: "Escaneo completado satisfactoriamente",
        data: scan,
      },
      { status: 201 }
    );
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : "Error durante la ejecución del escaneo";
    console.error("[Scans:POST] Error:", err);

    return NextResponse.json(
      { error: errorMsg },
      { status: errorMsg.includes("SSRF") || errorMsg.includes("bloqueado") ? 403 : 500 }
    );
  }
}
