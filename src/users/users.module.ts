import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';

@Module({
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService], // ⚠️ IMPORTANTE: Exportar para usar en AuthModule. Si no lo exportas no podras utilizar este servicio necesario en el modulo Auth
})
export class UsersModule { }