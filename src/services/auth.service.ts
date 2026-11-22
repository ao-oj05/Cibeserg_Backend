import { prisma } from "@/lib/db";
import { hashPassword, verifyPassword, createSessionToken } from "@/lib/auth";
import { AuditService } from "./audit.service";

export interface RegisterUserDto {
  email: string;
  password: string;
  name?: string;
}

export interface LoginUserDto {
  email: string;
  password: string;
}

export interface RequestContext {
  ipAddress: string;
  userAgent: string;
}

export class AuthService {
  /**
   * Registers a new user with Argon2id password hashing
   */
  static async register(dto: RegisterUserDto) {
    const existing = await prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existing) {
      throw new Error("ALREADY_EXISTS:Ya existe un usuario registrado con este correo");
    }

    const passwordHash = await hashPassword(dto.password);

    const user = await prisma.user.create({
      data: {
        email: dto.email,
        passwordHash,
        name: dto.name || null,
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

    return user;
  }

  /**
   * Authenticates user, verifies password, registers audit log and issues JWT token
   */
  static async login(dto: LoginUserDto, context: RequestContext) {
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
      throw new Error("CONFIG_ERROR:Configuración de autenticación inválida");
    }

    const user = await prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      await AuditService.log({
        action: "LOGIN_FAILED",
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        metadata: { reason: "Usuario no registrado", email: dto.email },
      });
      throw new Error("INVALID_CREDENTIALS:Credenciales de acceso incorrectas");
    }

    if (user.suspendedAt) {
      await AuditService.log({
        userId: user.id,
        action: "LOGIN_FAILED",
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        metadata: { reason: "Cuenta suspendida" },
      });
      throw new Error("ACCOUNT_SUSPENDED:Cuenta suspendida");
    }

    const isMatch = await verifyPassword(dto.password, user.passwordHash);

    if (!isMatch) {
      await AuditService.log({
        userId: user.id,
        action: "LOGIN_FAILED",
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        metadata: { reason: "Contraseña inválida" },
      });
      throw new Error("INVALID_CREDENTIALS:Credenciales de acceso incorrectas");
    }

    // Success audit log
    await AuditService.log({
      userId: user.id,
      action: "LOGIN_SUCCESS",
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });

    // Generate JWT token
    const token = await createSessionToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    return {
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
    };
  }

  /**
   * Handles user logout and registers audit log
   */
  static async logout(userId: string | null, context: RequestContext) {
    if (userId) {
      await AuditService.log({
        userId,
        action: "LOGOUT",
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
      });
    }
  }
}
