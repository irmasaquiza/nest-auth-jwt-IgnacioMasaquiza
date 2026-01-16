import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) { }

  /**
   * GET /users
   * Obtener todos los usuarios (sin contraseñas)
   * Ruta PROTEGIDA - requiere autenticación
   */
  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.usersService.findAll();
  }

  /**
   * GET /users/:id
   * Obtener un usuario por su ID
   * Ruta PROTEGIDA - requiere autenticación
   */
  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    const user = this.usersService.findById(+id);
    if (!user) {
      return { message: 'Usuario no encontrado' };
    }
    // Retornar sin contraseña  
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }
}
