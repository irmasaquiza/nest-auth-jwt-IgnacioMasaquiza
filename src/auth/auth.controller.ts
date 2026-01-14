import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Request
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  /**
   * POST /auth/register
   * Registro de nuevo usuario
   * Ruta PÚBLICA
   */
  @Post('register')
  register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  /**
   * POST /auth/login
   * Inicio de sesión
   * Ruta PÚBLICA
   */
  @Post('login')
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  /**
   * GET /auth/profile
   * Obtener perfil del usuario autenticado
   * Ruta PROTEGIDA - requiere token válido
   */
  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    // req.user viene del JwtStrategy.validate()
    return this.authService.getProfile(req.user.userId);
  }

  /**
   * GET /auth/protected
   * Ejemplo de ruta protegida
   * Ruta PROTEGIDA - requiere token válido
   */
  @UseGuards(JwtAuthGuard)
  @Get('protected')
  protectedRoute(@Request() req) {
    return {
      message: `¡Hola ${req.user.nombre}! Esta es una ruta protegida.`,
      timestamp: new Date().toISOString(),
      userId: req.user.userId,
    };
  }
}
