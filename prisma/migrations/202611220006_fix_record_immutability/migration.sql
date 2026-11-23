CREATE OR REPLACE FUNCTION enforce_record_immutability()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."createdAt" IS DISTINCT FROM OLD."createdAt" THEN
    RAISE EXCEPTION 'createdAt es inmutable';
  END IF;

  IF TG_TABLE_NAME = 'scans' THEN
    IF NEW."userId" IS DISTINCT FROM OLD."userId" THEN
      RAISE EXCEPTION 'No se permite reasignar el propietario';
    END IF;
  ELSIF TG_TABLE_NAME = 'findings' THEN
    IF NEW."scanId" IS DISTINCT FROM OLD."scanId" THEN
      RAISE EXCEPTION 'No se permite reasignar el escaneo';
    END IF;
  ELSIF TG_TABLE_NAME = 'reports' THEN
    IF NEW."userId" IS DISTINCT FROM OLD."userId"
       OR NEW."scanId" IS DISTINCT FROM OLD."scanId"
       OR NEW."type" IS DISTINCT FROM OLD."type" THEN
      RAISE EXCEPTION 'No se permite cambiar el propietario, escaneo o tipo';
    END IF;
  ELSIF TG_TABLE_NAME = 'notifications' THEN
    IF NEW."userId" IS DISTINCT FROM OLD."userId" THEN
      RAISE EXCEPTION 'No se permite reasignar el propietario';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;
