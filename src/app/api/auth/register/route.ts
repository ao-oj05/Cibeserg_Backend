import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { hashPassword } from "@/lib/auth";
import { RegisterSchema } from "@/lib/validators";

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

    const { email, password, name } = parseResult.data;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return NextResponse.json(
        { error: "Ya existe un usuario registrado con este correo electrónico" },
        { status: 409 }
      );
    }

    // Hash password with Argon2id
    const passwordHash = await hashPassword(password);

    // Create user
    const newUser = await prisma.user.create({
      data: {
        email,
        passwordHash,
        name: name || null,
        role: "USER",
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
    });

    return NextResponse.json(
      {
        message: "Usuario registrado satisfactoriamente",
        user: newUser,
      },
      { status: 201 }
    );
  } catch (err: unknown) {
    console.error("[Auth:Register] Error interno:", err);
    return NextResponse.json(
      { error: "Ocurrió un error al procesar el registro" },
      { status: 500 }
    );
  }
}
