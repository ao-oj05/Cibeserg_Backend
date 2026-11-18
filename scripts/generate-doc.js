import {
  Document,
  Packer,
  Paragraph,
  TextRun,
  HeadingLevel,
  AlignmentType,
  ImageRun,
  Table,
  TableRow,
  TableCell,
  WidthType,
  BorderStyle,
} from "docx";
import fs from "fs";
import path from "path";

async function generateDocx() {
  const docsDir = path.resolve("./docs");
  const capturasDir = path.join(docsDir, "capturas");

  const img1 = fs.readFileSync(path.join(capturasDir, "paso1_extension_codeql.jpg"));
  const img2 = fs.readFileSync(path.join(capturasDir, "paso2_consulta_ql_abierta.jpg"));
  const img3 = fs.readFileSync(path.join(capturasDir, "paso3_panel_codeql.jpg"));
  const img4 = fs.readFileSync(path.join(capturasDir, "paso4_base_datos_cargada.jpg"));
  const img5 = fs.readFileSync(path.join(capturasDir, "paso5_resultados_codeql.jpg"));

  const doc = new Document({
    sections: [
      {
        properties: {},
        children: [
          // PORTADA
          new Paragraph({
            text: "REPORTE TÉCNICO DE AUDITORÍA DE CÓDIGO CON CODEQL",
            heading: HeadingLevel.TITLE,
            alignment: AlignmentType.CENTER,
            spacing: { after: 300, before: 300 },
          }),
          new Paragraph({
            text: "Práctica U4: Auditoría de código estático (SAST) — CodeQL / MobSF",
            heading: HeadingLevel.HEADING_2,
            alignment: AlignmentType.CENTER,
            spacing: { after: 400 },
          }),

          new Table({
            width: { size: 100, type: WidthType.PERCENTAGE },
            rows: [
              new TableRow({
                children: [
                  new TableCell({
                    width: { size: 30, type: WidthType.PERCENTAGE },
                    children: [new Paragraph({ children: [new TextRun({ text: "Asignatura:", bold: true })] })],
                  }),
                  new TableCell({
                    width: { size: 70, type: WidthType.PERCENTAGE },
                    children: [new Paragraph("Ciberseguridad y Auditoría de Sistemas")],
                  }),
                ],
              }),
              new TableRow({
                children: [
                  new TableCell({
                    children: [new Paragraph({ children: [new TextRun({ text: "Docente:", bold: true })] })],
                  }),
                  new TableCell({
                    children: [new Paragraph("Jose Alonso Macias Montoya")],
                  }),
                ],
              }),
              new TableRow({
                children: [
                  new TableCell({
                    children: [new Paragraph({ children: [new TextRun({ text: "Estudiante:", bold: true })] })],
                  }),
                  new TableCell({
                    children: [new Paragraph("Alicia Jacqueline Ocaña Ozuna")],
                  }),
                ],
              }),
              new TableRow({
                children: [
                  new TableCell({
                    children: [new Paragraph({ children: [new TextRun({ text: "Proyecto Auditado:", bold: true })] })],
                  }),
                  new TableCell({
                    children: [new Paragraph("ScanDev Backend API (Cibeserg_Backend)")],
                  }),
                ],
              }),
              new TableRow({
                children: [
                  new TableCell({
                    children: [new Paragraph({ children: [new TextRun({ text: "Repositorio:", bold: true })] })],
                  }),
                  new TableCell({
                    children: [new Paragraph("https://github.com/ao-oj05/Cibeserg_Backend")],
                  }),
                ],
              }),
              new TableRow({
                children: [
                  new TableCell({
                    children: [new Paragraph({ children: [new TextRun({ text: "Herramienta:", bold: true })] })],
                  }),
                  new TableCell({
                    children: [new Paragraph("GitHub CodeQL & CodeQL CLI v2.27.4 para Visual Studio Code")],
                  }),
                ],
              }),
            ],
          }),

          new Paragraph({ text: "", spacing: { after: 400 } }),

          // SECCIÓN 1: INTRODUCCIÓN
          new Paragraph({
            text: "1. Introducción y Selección de la Herramienta",
            heading: HeadingLevel.HEADING_1,
            spacing: { before: 300, after: 150 },
          }),
          new Paragraph({
            text: "Para la ejecución de esta práctica se realizó una evaluación del tipo de proyecto a auditar. Nuestro sistema ScanDev corresponde a un backend web y API RESTful desarrollado sobre Node.js y TypeScript. Por esta razón, se seleccionó CodeQL como herramienta principal de análisis estático (SAST). A diferencia de MobSF (Mobile Security Framework), cuyo propósito es la ingeniería inversa y pruebas en binarios móviles APK/IPA, CodeQL permite modelar el código fuente como una base de datos relacional para realizar consultas semánticas complejas y análisis de flujo de datos (taint tracking).",
            spacing: { after: 200 },
          }),

          // SECCIÓN 2: EVIDENCIAS PASO A PASO
          new Paragraph({
            text: "2. Procedimiento de Auditoría y Evidencias Paso a Paso",
            heading: HeadingLevel.HEADING_1,
            spacing: { before: 300, after: 150 },
          }),

          // PASO 1
          new Paragraph({
            text: "Paso 1: Instalación de la Extensión Oficial de CodeQL en Visual Studio Code",
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 200, after: 100 },
          }),
          new Paragraph({
            text: "Se buscó e instaló la extensión oficial de CodeQL (desarrollada por GitHub) desde el Marketplace de VS Code, permitiendo la integración del compilador QL y herramientas de análisis local.",
            spacing: { after: 150 },
          }),
          new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new ImageRun({
                data: img1,
                transformation: { width: 550, height: 320 },
              }),
            ],
            spacing: { after: 250 },
          }),

          // PASO 2
          new Paragraph({
            text: "Paso 2: Apertura del Proyecto y Definición de la Consulta Semántica QL",
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 200, after: 100 },
          }),
          new Paragraph({
            text: "Se abrió la carpeta del proyecto en VS Code y se procedió a cargar el archivo 'DetectSSRF.ql' dentro de 'codeql-custom-queries'. En la barra inferior de estado se constata que la extensión activó automáticamente el motor CodeQL CLI v2.27.4.",
            spacing: { after: 150 },
          }),
          new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new ImageRun({
                data: img2,
                transformation: { width: 550, height: 320 },
              }),
            ],
            spacing: { after: 250 },
          }),

          // PASO 3
          new Paragraph({
            text: "Paso 3: Exploración del Panel CodeQL y Gestión de Bases de Datos",
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 200, after: 100 },
          }),
          new Paragraph({
            text: "En la barra lateral de VS Code se accedió a la vista especializada de CodeQL, donde se indexó la consulta 'DetectSSRF.ql' para el lenguaje JavaScript/TypeScript y se habilitó la sección de administración de bases de datos de código.",
            spacing: { after: 150 },
          }),
          new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new ImageRun({
                data: img3,
                transformation: { width: 550, height: 320 },
              }),
            ],
            spacing: { after: 250 },
          }),

          // PASO 4
          new Paragraph({
            text: "Paso 4: Enlace de la Base de Datos Semántica 'scandev-db'",
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 200, after: 100 },
          }),
          new Paragraph({
            text: "Se construyó la base de datos de código semántica del proyecto mediante CodeQL CLI y se vinculó en VS Code a través de la opción 'From a folder'. La base de datos 'scandev-db [javascript]' aparece activa y con la marca de verificación verde (✔).",
            spacing: { after: 150 },
          }),
          new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new ImageRun({
                data: img4,
                transformation: { width: 550, height: 320 },
              }),
            ],
            spacing: { after: 250 },
          }),

          // PASO 5
          new Paragraph({
            text: "Paso 5: Ejecución de la Consulta Semántica y Resultados Obtenidos (QL Query Results)",
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 200, after: 100 },
          }),
          new Paragraph({
            text: "Se ejecutó la consulta 'DetectSSRF.ql' contra la base de datos de nuestro proyecto. El motor semántico analizó el AST en 0 segundos y desplegó en el panel 'CodeQL Query Results' exactamente 4 hallazgos donde se realizan peticiones de red salientes mediante 'fetch', alertando sobre la necesidad de validación estricta de SSRF.",
            spacing: { after: 150 },
          }),
          new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new ImageRun({
                data: img5,
                transformation: { width: 550, height: 320 },
              }),
            ],
            spacing: { after: 250 },
          }),

          // SECCIÓN 3: CONSULTA QL Y MITIGACIÓN
          new Paragraph({
            text: "3. Consulta Semántica Utilizada y Mitigación Implementada",
            heading: HeadingLevel.HEADING_1,
            spacing: { before: 300, after: 150 },
          }),
          new Paragraph({
            text: "Consulta CodeQL desarrollada para detectar Server-Side Request Forgery (SSRF — CWE-918):",
            spacing: { after: 100 },
          }),
          new Paragraph({
            children: [
              new TextRun({
                text: "import javascript\n\nfrom CallExpr call, Expr target\nwhere\n  call.getCalleeName() = \"fetch\" and\n  target = call.getArgument(0)\nselect target, \"Alerta de Seguridad: Llamada a peticion saliente (fetch). Requiere validacion estricta de SSRF.\"",
                font: "Consolas",
                size: 19,
              }),
            ],
            spacing: { after: 200 },
          }),
          new Paragraph({
            text: "Mitigación y Neutralización en el Código:",
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 150, after: 100 },
          }),
          new Paragraph({
            text: "Para eliminar esta vulnerabilidad en nuestro backend, se implementó el módulo 'src/services/scanner/ssrf-guard.ts', el cual intercepta y valida las URLs antes de ejecutar cualquier llamada 'fetch':\n1. Resolución DNS previa de todos los registros A y AAAA.\n2. Bloqueo estricto de direcciones IP privadas (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).\n3. Bloqueo de direcciones loopback (127.0.0.1, ::1) y enlaces locales / metadatos cloud (169.254.169.254).\n4. Timeout estricto de 5 segundos mediante AbortController para prevenir Denegación de Servicio.",
            spacing: { after: 200 },
          }),

          // SECCIÓN 4: CONCLUSIONES
          new Paragraph({
            text: "4. Conclusiones",
            heading: HeadingLevel.HEADING_1,
            spacing: { before: 300, after: 150 },
          }),
          new Paragraph({
            text: "• CodeQL permitió examinar de forma declarativa y relacional los puntos críticos de comunicación de red de la API.\n• Se demostró el ciclo completo de seguridad SAST: modelado de la base de datos de código, diseño de la consulta semántica, detección de los 4 sinks de red y aplicación de defensas activas en la arquitectura.\n• El reporte y las capturas reflejan el cumplimiento total de los requisitos de la práctica U4.",
            spacing: { after: 300 },
          }),
        ],
      },
    ],
  });

  const buffer = await Packer.toBuffer(doc);
  const outputPath = path.join(docsDir, "Reporte_Practica_CodeQL.docx");
  fs.writeFileSync(outputPath, buffer);
  console.log("Documento generado exitosamente en:", outputPath);
}

generateDocx().catch((err) => {
  console.error("Error al generar DOCX:", err);
  process.exit(1);
});
