import { Injectable } from '@nestjs/common';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
  // Simulamos base de datos con un array
  private users: User[] = [];
  private idCounter = 1;

  // Crear nuevo usuario
  create(userData: Omit<User, 'id' | 'createdAt'>): User {
    const newUser: User = {
      id: this.idCounter++,
      ...userData,
      createdAt: new Date(),
    };
    this.users.push(newUser);
    return newUser;
  }

  // Buscar usuario por email
  findByEmail(email: string): User | undefined {
    return this.users.find((user) => user.email === email);
  }

  // Buscar usuario por ID
  findById(id: number): User | undefined {
    return this.users.find((user) => user.id === id);
  }

  // Obtener todos los usuarios (sin contraseñas)
  findAll(): Omit<User, 'password'>[] {
    return this.users.map(({ password, ...userWithoutPassword }) => userWithoutPassword);
  }
}