import { z } from "zod";

const EnvironmentSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  DATABASE_URL: z
    .string()
    .url("Debe ser una URL válida")
    .refine((value) => /^postgres(?:ql)?:\/\//i.test(value), {
      message: "Debe usar el protocolo PostgreSQL",
    }),
  JWT_SECRET: z.string().min(32, "Debe contener al menos 32 caracteres"),
  STORAGE_REPORTS_DIR: z.string().min(1).default("./storage/reports"),
});

export type Environment = z.infer<typeof EnvironmentSchema>;

export function parseEnvironment(source: NodeJS.ProcessEnv): Environment {
  const result = EnvironmentSchema.safeParse(source);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
      .join("; ");
    throw new Error(`Configuración de entorno inválida: ${details}`);
  }
  return result.data;
}

export const env = parseEnvironment(process.env);
