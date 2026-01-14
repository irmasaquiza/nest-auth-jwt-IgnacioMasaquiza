import {
    Injectable,
    ConflictException,
    UnauthorizedException
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
    ) { }

    /**
     * REGISTRO DE USUARIO
     * 1. Verifica que el email no exista
     * 2. Hashea la contraseña
     * 3. Crea el usuario
     * 4. Retorna usuario sin contraseña
     */
    async register(registerDto: RegisterDto) {
        // 1. Verificar si el email ya está registrado
        const existingUser = this.usersService.findByEmail(registerDto.email);
        if (existingUser) {
            throw new ConflictException('El email ya está registrado');
        }

        // 2. Hashear la contraseña con bcrypt (10 rondas de salt)
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(registerDto.password, saltRounds);

        // 3. Crear el usuario con la contraseña hasheada
        // Combinamos name y lastName para formar el nombre completo
        const newUser = this.usersService.create({
            nombre: `${registerDto.name} ${registerDto.lastName}`,
            email: registerDto.email,
            password: hashedPassword,
            isActive: true,
            role: 'user',
        });

        // 4. Retornar respuesta sin incluir la contraseña
        const { password, ...userWithoutPassword } = newUser;

        return {
            message: 'Usuario registrado exitosamente',
            user: userWithoutPassword,
        };
    }

    /**
     * LOGIN DE USUARIO
     * 1. Busca usuario por email
     * 2. Verifica contraseña
     * 3. Genera token JWT
     * 4. Retorna token y datos del usuario
     */
    async login(loginDto: LoginDto) {
        // 1. Buscar usuario por email
        const user = this.usersService.findByEmail(loginDto.email);
        if (!user) {
            throw new UnauthorizedException('Credenciales inválidas');
        }

        // 2. Verificar que la cuenta esté activa
        if (!user.isActive) {
            throw new UnauthorizedException('La cuenta está desactivada');
        }

        // 3. Comparar la contraseña proporcionada con el hash almacenado
        const isPasswordValid = await bcrypt.compare(loginDto.password, user.password);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Credenciales inválidas');
        }

        // 4. Crear el payload del token JWT
        // `sub` es una convención de JWT que significa "subject" (el ID del usuario)
        const payload = {
            sub: user.id,
            email: user.email,
            nombre: user.nombre,
            role: user.role,
        };

        // 5. Generar el token JWT firmado
        const accessToken = this.jwtService.sign(payload);

        // 6. Retornar el token y los datos del usuario (sin contraseña)
        return {
            message: 'Login exitoso',
            access_token: accessToken,
            user: {
                id: user.id,
                nombre: user.nombre,
                email: user.email,
                role: user.role,
            },
        };
    }

    /**
     * OBTENER PERFIL
     * Retorna información del usuario autenticado
     */
    getProfile(userId: number) {
        // Buscar el usuario por ID
        const user = this.usersService.findById(userId);

        if (!user) {
            throw new UnauthorizedException('Usuario no encontrado');
        }

        // Retornar datos del usuario sin la contraseña
        const { password, ...userWithoutPassword } = user;

        return {
            message: 'Perfil obtenido exitosamente',
            user: userWithoutPassword,
        };
    }
}