import { readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';

function isMissingFile(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}

export async function readStoredReport(
  storageDirectory: string,
  storedPath: string,
): Promise<Buffer> {
  let storageRoot: string;
  let reportPath: string;
  try {
    [storageRoot, reportPath] = await Promise.all([
      realpath(path.resolve(storageDirectory)),
      realpath(path.resolve(storedPath)),
    ]);
  } catch (error) {
    if (isMissingFile(error)) {
      throw new Error('NOT_FOUND:El archivo físico del reporte no existe en el almacenamiento');
    }
    throw error;
  }

  const relativePath = path.relative(storageRoot, reportPath);
  if (
    !relativePath ||
    relativePath === '..' ||
    relativePath.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relativePath)
  ) {
    throw new Error('FORBIDDEN:Acceso no autorizado al sistema de archivos');
  }

  const fileStats = await stat(reportPath);
  if (!fileStats.isFile()) {
    throw new Error('FORBIDDEN:El reporte no es un archivo regular');
  }

  return readFile(reportPath);
}
