import { NextRequest, NextResponse } from "next/server";
import { RegisterSchema } from "@/lib/validators";
import { AuthService } from "@/services/auth.service";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const parseResult = RegisterSchema.safeParse(body);

    if (!parseResult.success) {
      return NextResponse.json(
        {
          error: "Datos de registro inválidos",
          details: parseResult.error.flatten().fieldErrors,
        },
        { status: 400 }
      );
    }

    const user = await AuthService.register(parseResult.data);

    return NextResponse.json(
      {
        message: "Usuario registrado satisfactoriamente",
        user,
      },
      { status: 201 }
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Error al procesar registro";
    if (message.startsWith("ALREADY_EXISTS:")) {
      return NextResponse.json({ error: message.replace("ALREADY_EXISTS:", "") }, { status: 409 });
    }
    console.error("[Auth:Register] Error:", err);
    return NextResponse.json({ error: "Error interno al procesar el registro" }, { status: 500 });
  }
}
