import { prisma } from "@/lib/db";
import { generateSecurityPdfReport } from "./report-generator";
import { AuditService } from "./audit.service";
import { sanitizeCsvCell } from "@/lib/validators";
import { readStoredReport } from "@/lib/report-storage";
import { env } from "@/lib/env";
import { ReportType } from "@prisma/client";
import crypto from "crypto";

export interface GenerateReportDto {
  scanId?: string;
  type: ReportType;
}

export class ReportService {
  /**
   * Lists all reports belonging to the user
   */
  static async listReports(userId: string) {
    return await prisma.report.findMany({
      where: { userId },
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
  }

  /**
   * Generates a new PDF report with a 7-day expiration window (BK-07)
   */
  static async generateReport(userId: string, userEmail: string, dto: GenerateReportDto) {
    let scanData = null;

    if (dto.scanId) {
      scanData = await prisma.scan.findFirst({
        where: {
          id: dto.scanId,
          userId, // Strict ownership check
        },
        include: {
          findings: true,
        },
      });

      if (!scanData) {
        throw new Error("NOT_FOUND:El escaneo especificado no pertenece al usuario o no existe");
      }
    }

    const reportId = crypto.randomUUID();

    // Generate physical PDF
    const { fileName, filePath } = await generateSecurityPdfReport({
      reportId,
      type: dto.type,
      scan: scanData,
      userEmail,
    });

    // 7 days expiration
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Save record
    const report = await prisma.report.create({
      data: {
        id: reportId,
        userId,
        scanId: dto.scanId || null,
        type: dto.type,
        fileName,
        filePath,
        expiresAt,
      },
    });

    await AuditService.log({
      userId,
      action: "REPORT_GENERATED",
      metadata: { reportId: report.id, type: dto.type, scanId: dto.scanId },
    });

    return report;
  }

  /**
   * Verifies file existence, expiration and ownership, returning file buffer for download
   */
  static async getDownloadableReport(userId: string, reportId: string) {
    const report = await prisma.report.findFirst({
      where: {
        id: reportId,
        userId,
      },
    });

    if (!report) {
      throw new Error("NOT_FOUND:Reporte no encontrado o no tiene autorización");
    }

    // Expiration check (BK-07)
    if (new Date() > new Date(report.expiresAt)) {
      throw new Error("EXPIRED:El enlace de descarga del reporte ha expirado (7 días)");
    }

    // Path traversal check
    const storageDirectory = env.STORAGE_REPORTS_DIR;
    const buffer = await readStoredReport(storageDirectory, report.filePath);
    return {
      fileName: report.fileName,
      buffer,
    };
  }

  /**
   * Generates sanitized CSV string of all user scans (BK-07)
   */
  static async exportScansToCsv(userId: string) {
    const scans = await prisma.scan.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
      include: {
        _count: {
          select: { findings: true },
        },
      },
    });

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

    return [headers.join(","), ...rows.map((r) => r.join(","))].join("\r\n");
  }
}
