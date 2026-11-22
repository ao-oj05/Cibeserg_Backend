import { z } from "zod";

/**
 * User Registration Validation Schema
 */
export const RegisterSchema = z.object({
  email: z
    .string()
    .trim()
    .toLowerCase()
    .email({ message: "Formato de correo electrónico inválido" })
    .max(255),
  password: z
    .string()
    .min(8, { message: "La contraseña debe tener al menos 8 caracteres" })
    .max(128, { message: "La contraseña no debe exceder 128 caracteres" })
    .regex(/[A-Z]/, { message: "Debe contener al menos una letra mayúscula" })
    .regex(/[a-z]/, { message: "Debe contener al menos una letra minúscula" })
    .regex(/[0-9]/, { message: "Debe contener al menos un número" })
    .regex(/[^A-Za-z0-9]/, { message: "Debe contener al menos un carácter especial" }),
  name: z.string().trim().min(2).max(100).optional(),
});

/**
 * User Login Validation Schema
 */
export const LoginSchema = z.object({
  email: z.string().trim().toLowerCase().email({ message: "Correo electrónico requerido" }),
  password: z.string().min(1, { message: "Contraseña requerida" }),
});

/**
 * New Scan Request Validation Schema
 */
export const CreateScanSchema = z.object({
  targetUrl: z
    .string()
    .trim()
    .min(3)
    .max(2048)
    .refine(
      (val) => {
        try {
          const parsed = new URL(val.startsWith("http://") || val.startsWith("https://") ? val : `https://${val}`);
          return parsed.protocol === "http:" || parsed.protocol === "https:";
        } catch {
          return false;
        }
      },
      { message: "La URL debe ser válida y usar protocolo http o https" }
    )
    .transform((val) => {
      // Normalize URL: ensure protocol exists
      if (!val.startsWith("http://") && !val.startsWith("https://")) {
        return `https://${val}`;
      }
      return val;
    }),
});

/**
 * Scan List Query Validation Schema
 */
export const ScanQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100).default(10),
  host: z.string().trim().max(255).optional(),
});

/**
 * Report Generation Validation Schema
 */
export const CreateReportSchema = z.object({
  scanId: z.string().uuid().optional(),
  type: z.enum(["EXECUTIVE", "TECHNICAL", "COMPARATIVE"]).default("EXECUTIVE"),
});

/**
 * Notifications Update Schema
 */
export const UpdateNotificationsSchema = z.object({
  notificationIds: z.array(z.string().uuid()).min(1),
});

/**
 * Sanitizes input for CSV export to prevent CSV Formula Injection (BK-07).
 * Prepend a single quote when a cell starts with a formula trigger or control whitespace.
 */
export function sanitizeCsvCell(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  let str = String(value);

  // Check for formula injection triggers
  const formulaAfterWhitespace = /^[\s\uFEFF]*[=+\-@]/.test(str);
  const startsWithControlWhitespace = /^[\t\r\n]/.test(str);
  if (formulaAfterWhitespace || startsWithControlWhitespace) {
    str = `'${str}`;
  }

  // Escape double quotes and enclose in quotes if contains commas, line breaks or double quotes
  if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
    return `"${str.replace(/"/g, '""')}"`;
  }

  return str;
}

/**
 * Escapes special SQL wildcard characters (%, _, \) to prevent query manipulation in LIKE operations.
 */
export function escapeSqlLike(value: string): string {
  return value.replace(/[%_\\]/g, "\\$&");
}
