import PDFDocument from "pdfkit";
import fs from "fs";
import path from "path";
import { env } from "@/lib/env";

export interface GeneratePdfOptions {
  reportId: string;
  type: "EXECUTIVE" | "TECHNICAL" | "COMPARATIVE";
  scan?: {
    id: string;
    host: string;
    targetUrl: string;
    riskScore: number;
    responseTimeMs: number | null;
    httpsRedirect: boolean;
    sslValid: boolean;
    sslIssuer: string | null;
    sslDaysLeft: number | null;
    sslProtocol: string | null;
    completedAt: Date | null;
    findings?: Array<{
      category: string;
      checkKey: string;
      title: string;
      description: string;
      status: string;
      severity: string;
      remediation?: string | null;
    }>;
  } | null;
  userEmail: string;
}

export async function generateSecurityPdfReport(options: GeneratePdfOptions): Promise<{ fileName: string; filePath: string }> {
  const reportsDir = path.resolve(env.STORAGE_REPORTS_DIR);

  // Ensure storage/reports directory exists
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }

  const fileName = `scandev-report-${options.type.toLowerCase()}-${options.reportId}.pdf`;
  const filePath = path.join(reportsDir, fileName);

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: "A4" });
    const writeStream = fs.createWriteStream(filePath);

    doc.pipe(writeStream);

    // Header Branding
    doc
      .fillColor("#0f172a")
      .fontSize(22)
      .text("ScanDev — Reporte de Ciberseguridad", { align: "left" })
      .moveDown(0.2);

    doc
      .fillColor("#64748b")
      .fontSize(10)
      .text(`Tipo de Reporte: ${options.type} | Generado para: ${options.userEmail} | Fecha: ${new Date().toLocaleDateString()}`)
      .moveDown(1.5);

    doc.strokeColor("#e2e8f0").lineWidth(1).moveTo(50, doc.y).lineTo(545, doc.y).stroke().moveDown(1);

    if (options.scan) {
      const scan = options.scan;
      const riskLevel = scan.riskScore >= 80 ? "Bajo Riesgo (Seguro)" : scan.riskScore >= 60 ? "Riesgo Medio" : "Riesgo Alto (Crítico)";
      const riskColor = scan.riskScore >= 80 ? "#16a34a" : scan.riskScore >= 60 ? "#d97706" : "#dc2626";

      // Score Card
      doc
        .fillColor("#1e293b")
        .fontSize(14)
        .text("Resumen de Evaluación del Objetivo")
        .moveDown(0.5);

      doc
        .fontSize(11)
        .fillColor("#334155")
        .text(`• Dominio / Host: ${scan.host}`)
        .text(`• URL Auditada: ${scan.targetUrl}`)
        .text(`• Tiempo de Respuesta: ${scan.responseTimeMs ?? "N/A"} ms`)
        .text(`• Redirección Forzada a HTTPS: ${scan.httpsRedirect ? "Habilitada" : "Deshabilitada"}`)
        .text(`• Certificado SSL/TLS: ${scan.sslValid ? "Válido" : "Inválido / Inseguro"} (Emisor: ${scan.sslIssuer ?? "N/A"})`)
        .text(`• Días de Vigencia SSL: ${scan.sslDaysLeft ?? "N/A"} días`)
        .text(`• Protocolo TLS Negociado: ${scan.sslProtocol ?? "N/A"}`)
        .moveDown(0.8);

      doc
        .fillColor(riskColor)
        .fontSize(16)
        .text(`Calificación de Seguridad: ${scan.riskScore} / 100 — [${riskLevel}]`)
        .moveDown(1.5);

      // Detailed Findings
      if (options.type === "TECHNICAL" && scan.findings && scan.findings.length > 0) {
        doc
          .fillColor("#0f172a")
          .fontSize(14)
          .text("Detalle Técnico de Comprobaciones y Hallazgos")
          .moveDown(0.5);

        scan.findings.forEach((finding, idx) => {
          const statusColor = finding.status === "PASSED" ? "#16a34a" : "#dc2626";
          doc
            .fontSize(10)
            .fillColor("#1e293b")
            .text(`${idx + 1}. ${finding.title} [Severidad: ${finding.severity}]`, { continued: true })
            .fillColor(statusColor)
            .text(` — ${finding.status}`)
            .fillColor("#475569")
            .text(`   Detalle: ${finding.description}`);

          if (finding.remediation) {
            doc.fillColor("#2563eb").text(`   Remediación: ${finding.remediation}`);
          }
          doc.moveDown(0.4);
        });
      }
    } else {
      doc
        .fillColor("#334155")
        .fontSize(12)
        .text("Informe global consolidado de auditorías y métricas de seguridad de la cuenta.")
        .moveDown();
    }

    // Footer
    doc
      .fontSize(9)
      .fillColor("#94a3b8")
      .text(
        "ScanDev Security Engine — Auditorías no invasivas pasivas de ciberseguridad. Documento confidencial.",
        50,
        780,
        { align: "center", width: 500 }
      );

    doc.end();

    writeStream.on("finish", () => {
      resolve({ fileName, filePath });
    });

    writeStream.on("error", (err) => {
      reject(err);
    });
  });
}
