import { NextRequest, NextResponse } from 'next/server';
import { getSessionUser } from '@/lib/auth';
import { CreateScanSchema, ScanQuerySchema } from '@/lib/validators';
import { ScanService } from '@/services/scan.service';

export const runtime = 'nodejs';

/**
 * GET /api/scans
 * Lista el historial de escaneos del usuario autenticado (BK-05).
 */
export async function GET(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const { searchParams } = new URL(req.url);
    const queryResult = ScanQuerySchema.safeParse({
      page: searchParams.get('page') ?? undefined,
      limit: searchParams.get('limit') ?? undefined,
      host: searchParams.get('host') ?? undefined,
    });

    if (!queryResult.success) {
      return NextResponse.json(
        { error: 'Parámetros de consulta inválidos' },
        { status: 400 },
      );
    }

    const result = await ScanService.listUserScans(session.userId, queryResult.data);
    return NextResponse.json(result);
  } catch (err: unknown) {
    console.error('[Scans:GET] Error:', err);
    return NextResponse.json(
      { error: 'Error al consultar historial de escaneos' },
      { status: 500 },
    );
  }
}

/**
 * POST /api/scans
 * Encola un nuevo escaneo de seguridad pasivo.
 *
 * Body esperado:
 * {
 *   "targetUrl": "https://example.com",
 *   "confirmedOwnership": true          ← RS-02: obligatorio
 * }
 *
 * Requerimientos aplicados:
 * - BK-02: Rate limiting (manejado en ScanService)
 * - BK-03: Validación Zod del body
 * - RS-02: confirmedOwnership = true obligatorio
 */
export async function POST(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const ipAddress =
      req.headers.get('x-forwarded-for')?.split(',')[0].trim() ?? '127.0.0.1';

    const body = await req.json();

    // BK-03: Validación de URL con Zod
    const parseResult = CreateScanSchema.safeParse(body);
    if (!parseResult.success) {
      return NextResponse.json(
        {
          error: 'URL objetivo inválida',
          details: parseResult.error.flatten().fieldErrors,
        },
        { status: 400 },
      );
    }

    // RS-02: Verificar confirmedOwnership explícitamente en el controlador
    const confirmedOwnership = body?.confirmedOwnership;
    if (confirmedOwnership !== true) {
      return NextResponse.json(
        {
          error:
            'Debes confirmar que eres propietario o tienes autorización para escanear este dominio (RS-02).',
        },
        { status: 400 },
      );
    }

    const scan = await ScanService.startScan(
      session.userId,
      parseResult.data.targetUrl,
      ipAddress,
      true, // confirmedOwnership ya verificado arriba
    );

    return NextResponse.json(
      { message: 'Escaneo aceptado y en cola', data: scan },
      { status: 202 },
    );
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : 'Error durante la ejecución del escaneo';

    if (message.startsWith('RATE_LIMIT:')) {
      return NextResponse.json(
        { error: message.replace('RATE_LIMIT:', '') },
        { status: 429 },
      );
    }
    if (message.startsWith('QUEUE_FULL:')) {
      return NextResponse.json(
        { error: message.replace('QUEUE_FULL:', '') },
        { status: 503 },
      );
    }
    if (message.startsWith('RS-02:')) {
      return NextResponse.json(
        { error: message.replace('RS-02:', '') },
        { status: 400 },
      );
    }
    if (message.includes('SSRF') || message.includes('bloqueado')) {
      return NextResponse.json({ error: 'Objetivo de escaneo no permitido.' }, { status: 403 });
    }

    console.error('[Scans:POST] Error:', err);
    return NextResponse.json(
      { error: 'Error interno al ejecutar el escaneo.' },
      { status: 500 },
    );
  }
}
