# Taller: Autenticación con JWT y Guards en NestJS
## Desarrollo en Plataformas - PUCE

---

## Información del Taller

| Aspecto | Detalle |
|---------|---------|
| **Tema** | Autenticación JWT en APIs REST |
| **Duración estimada** | 2 horas |
| **Entregable** | Proyecto NestJS con registro, login y rutas protegidas |

---

## Objetivos

Al completar este taller podrás:
- ✅ Implementar registro de usuarios con contraseñas hasheadas
- ✅ Crear sistema de login que genera tokens JWT
- ✅ Proteger rutas usando Guards
- ✅ Acceder a la información del usuario autenticado

---

## Conceptos Clave

### ¿Qué es JWT?

JWT (JSON Web Token) es como un **brazalete de hotel all-inclusive**:
- Te registras (login) → recibes un brazalete (token)
- Para acceder al buffet, piscina, bar → muestras el brazalete
- El personal verifica el brazalete sin llamar a recepción cada vez
- Si alguien falsifica el brazalete → el código no coincide y se rechaza

### ¿Qué es un Guard?

Un Guard es un **guardia de seguridad** que verifica tu token antes de dejarte entrar a una ruta protegida.

---

## Parte 1: Configuración del Proyecto

### Paso 1.1: Crear proyecto NestJS

```bash
nest new auth-taller
cd auth-taller
```

### Paso 1.2: Instalar dependencias

```bash
npm install @nestjs/jwt @nestjs/passport passport passport-jwt bcrypt class-validator class-transformer
npm install -D @types/passport-jwt @types/bcrypt
```

### Paso 1.3: Generar módulos con CLI

```bash
# Módulo de autenticación (sin CRUD)
nest g resource auth --no-spec
# Seleccionar: REST API → No

# Módulo de usuarios (con CRUD)
nest g resource users --no-spec
# Seleccionar: REST API → Yes
```

### Paso 1.4: Habilitar validación global

Editar `src/main.ts`:

```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Habilitar validación automática de DTOs
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,  // Elimina propiedades no definidas en el DTO
    transform: true,  // Transforma tipos automáticamente
  }));
  
  await app.listen(3000);
  console.log('🚀 Servidor corriendo en http://localhost:3000');
}
bootstrap();
```

---

## Parte 2: Módulo de Usuarios

### Paso 2.1: Definir la entidad de Usuario

Editar `src/users/entities/user.entity.ts`:

```typescript
export class User {
  // genera un prompt para que agrege las columnas, consus caracteristicas, bien detallado
}
```

### Paso 2.2: Implementar el servicio de usuarios

Editar `src/users/users.service.ts`:

```typescript
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
	// genera el codigo
  }

  // Buscar usuario por ID
  findById(id: number): User | undefined {
	// genera el codigo
  }

  // Obtener todos los usuarios (sin contraseñas)
  findAll(): Omit<User, 'password'>[] {
	// genera el codigo
  }
}
```

### Paso 2.3: Exportar el servicio

Editar `src/users/users.module.ts`:

```typescript
import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';

@Module({
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService], // ⚠️ IMPORTANTE: Exportar para usar en AuthModule. Si no lo exportas no podras utilizar este servicio necesario en el modulo Auth
})
export class UsersModule {}
```

---

## Parte 3: DTOs de Autenticación

### Paso 3.1: Crear DTO de Registro

Crear archivo `src/auth/dto/register.dto.ts`:

```typescript
import { IsEmail, IsString, MinLength, MaxLength } from 'class-validator';

export class RegisterDto {
  // Que deberia tener este DTO?
}
```

### Paso 3.2: Crear DTO de Login

Crear archivo `src/auth/dto/login.dto.ts`:

```typescript
import { IsEmail, IsString } from 'class-validator';

export class LoginDto {
  // Que deberia tener este DTO?
}
```

---

## Parte 4: Servicio de Autenticación

### Paso 4.1: Implementar AuthService

Editar `src/auth/auth.service.ts`:

```typescript
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
  ) {}

  /**
   * REGISTRO DE USUARIO
   * 1. Verifica que el email no exista
   * 2. Hashea la contraseña
   * 3. Crea el usuario
   * 4. Retorna usuario sin contraseña
   * 5. algo mas? esta bien este algoritmo?
   */
  async register(registerDto: RegisterDto) {
    // implementa el algoritmo
    
    return {
      // Retorna una respuesta
    };
  }

  /**
   * LOGIN DE USUARIO
   * 1. Busca usuario por email
   * 2. Verifica contraseña
   * 3. Genera token JWT
   * 4. Qué debería retornar?
   */
  async login(loginDto: LoginDto) {
   // Desarrolla la logica

    return {
      Qué retornamos
    };
  }

  /**
   * OBTENER PERFIL
   * Retorna información del usuario autenticado
   */
  getProfile(userId: number) {
   // Desarrolla la logica
  }
}
```

---

## Parte 5: Estrategia JWT y Guard

### Paso 5.1: Crear estrategia JWT

Crear archivo `src/auth/strategies/jwt.strategy.ts`:

```typescript
// src/auth/strategies/jwt.strategy.ts

// ============================================
// IMPORTACIONES NECESARIAS
// ============================================

// Injectable: Decorador que permite inyectar este servicio en otros componentes
import { Injectable } from '@nestjs/common';

// PassportStrategy: Clase base que conecta NestJS con la librería Passport
// Passport es una librería de autenticación muy popular en Node.js
import { PassportStrategy } from '@nestjs/passport';

// ExtractJwt: Utilidad que nos ayuda a extraer el token de diferentes lugares
// Strategy: La estrategia específica para validar tokens JWT
import { ExtractJwt, Strategy } from 'passport-jwt';

// ============================================
// CONFIGURACIÓN DEL SECRETO
// ============================================

// JWT_SECRET: Clave secreta usada para FIRMAR y VERIFICAR tokens
// - Esta clave NUNCA debe compartirse públicamente
// - En producción, debe estar en variables de entorno (.env)
// - Si alguien conoce esta clave, puede crear tokens falsos
// - Debe ser una cadena larga y aleatoria
export const JWT_SECRET = 'mi_clave_secreta_muy_segura_2024';

// ============================================
// ESTRATEGIA JWT
// ============================================

// @Injectable(): Marca esta clase como un "proveedor" de NestJS
// Esto permite que NestJS la inyecte automáticamente donde se necesite
@Injectable()

// La clase extiende PassportStrategy y le pasa la Strategy de JWT
// Esto conecta nuestra estrategia con el sistema de autenticación de Passport
export class JwtStrategy extends PassportStrategy(Strategy) {
  
  // ==========================================
  // CONSTRUCTOR: CONFIGURACIÓN DE LA ESTRATEGIA
  // ==========================================
  constructor() {
    // super() llama al constructor de la clase padre (PassportStrategy)
    // Le pasamos un objeto de configuración con las opciones de JWT
    super({
      
      // ------------------------------------------
      // jwtFromRequest: ¿De dónde extraemos el token?
      // ------------------------------------------
      // ExtractJwt.fromAuthHeaderAsBearerToken() busca el token en:
      // Header HTTP: "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
      //                              ^^^^^^^ Prefijo obligatorio
      //                                      ^^^^^^^^^^^^^^^^^^^^^ Token JWT
      // 
      // Otras opciones disponibles (no usadas aquí):
      // - fromHeader('x-token'): Busca en un header personalizado
      // - fromBodyField('token'): Busca en el body de la petición
      // - fromUrlQueryParameter('token'): Busca en ?token=xxx
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),

      // ------------------------------------------
      // ignoreExpiration: ¿Aceptamos tokens expirados?
      // ------------------------------------------
      // false = NO aceptar tokens expirados (RECOMENDADO para seguridad)
      // true  = Aceptar tokens aunque hayan expirado (INSEGURO)
      //
      // Cuando un token expira, el usuario debe hacer login nuevamente
      // Esto es una medida de seguridad: si alguien roba un token,
      // solo funcionará por tiempo limitado
      ignoreExpiration: false,

      // ------------------------------------------
      // secretOrKey: Clave para VERIFICAR la firma del token
      // ------------------------------------------
      // Esta debe ser EXACTAMENTE la misma clave usada para FIRMAR el token
      // Si las claves no coinciden, el token será rechazado
      //
      // ¿Cómo funciona la verificación?
      // 1. El servidor recibe el token
      // 2. Extrae el header y payload del token
      // 3. Usa esta clave para recalcular la firma
      // 4. Compara la firma calculada con la firma del token
      // 5. Si coinciden → token válido, si no → token rechazado
      secretOrKey: JWT_SECRET,
    });
  }

  // ==========================================
  // MÉTODO VALIDATE: PROCESAR TOKEN VÁLIDO
  // ==========================================
  
  // Este método se ejecuta AUTOMÁTICAMENTE cuando:
  // 1. Se recibe un token en el header Authorization
  // 2. El token tiene una firma válida (verificada con secretOrKey)
  // 3. El token NO ha expirado (si ignoreExpiration es false)
  //
  // IMPORTANTE: Si llegamos aquí, el token YA FUE VALIDADO
  // No necesitamos verificar la firma manualmente
  //
  // Parámetro "payload": Es el contenido decodificado del token
  // Ejemplo de payload que recibiríamos:
  // {
  //   sub: 1,                    // ID del usuario (subject)
  //   email: "juan@test.com",    // Email del usuario
  //   nombre: "Juan Pérez",      // Nombre del usuario
  //   iat: 1705312200,           // Issued At: cuándo se creó el token
  //   exp: 1705398600            // Expiration: cuándo expira el token
  // }
  async validate(payload: any) {
    
    // Lo que retornemos aquí se adjuntará a la petición HTTP
    // Estará disponible en req.user en cualquier controlador
    //
    // Ejemplo de uso en un controlador:
    // @Get('profile')
    // getProfile(@Request() req) {
    //   console.log(req.user.userId);  // 1
    //   console.log(req.user.email);   // "juan@test.com"
    // }
    //
    // NOTA: Retornamos solo los datos necesarios, no todo el payload
    // Esto es una buena práctica de seguridad (principio de mínimo privilegio)
    return {
      userId: payload.sub,      // Mapeamos "sub" a "userId" para mayor claridad
      email: payload.email,     // Email del usuario autenticado
      nombre: payload.nombre,   // Nombre del usuario autenticado
    };
    
    // NOTA AVANZADA: Aquí podríamos hacer validaciones adicionales:
    // - Verificar que el usuario aún existe en la base de datos
    // - Verificar que el usuario no esté bloqueado
    // - Verificar que el token no esté en una "lista negra"
    // 
    // Ejemplo:
    // const user = await this.usersService.findById(payload.sub);
    // if (!user) {
    //   throw new UnauthorizedException('Usuario no encontrado');
    // }
    // if (user.bloqueado) {
    //   throw new UnauthorizedException('Usuario bloqueado');
    // }
    // return user;
  }
}

// ============================================
// FLUJO COMPLETO DE AUTENTICACIÓN
// ============================================
//
// 1. Usuario hace login → recibe token JWT
//
// 2. Usuario hace petición a ruta protegida:
//    GET /auth/profile
//    Headers: { Authorization: "Bearer eyJhbGciOiJIUzI1NiIs..." }
//
// 3. JwtAuthGuard intercepta la petición
//
// 4. Guard llama a JwtStrategy automáticamente
//
// 5. JwtStrategy:
//    a) Extrae token del header (jwtFromRequest)
//    b) Verifica firma con la clave secreta (secretOrKey)
//    c) Verifica que no haya expirado (ignoreExpiration)
//    d) Si todo OK → llama a validate() con el payload
//    e) Si algo falla → lanza error 401 Unauthorized
//
// 6. validate() retorna objeto con datos del usuario
//
// 7. Guard permite continuar, datos disponibles en req.user
//
// 8. Controlador procesa la petición con acceso a req.user
```

### Paso 5.2: Crear el Guard

Crear archivo `src/auth/guards/jwt-auth.guard.ts`:

```typescript
import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any) {
    // Si hay error o no hay usuario, lanzar excepción
    if (err || !user) {
      throw err || new UnauthorizedException('Token inválido o expirado');
    }
    return user;
  }
}
```

---

## Parte 6: Configurar Módulo Auth

### Paso 6.1: Configurar AuthModule

Editar `src/auth/auth.module.ts`:

```typescript
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { JwtStrategy, JWT_SECRET } from './strategies/jwt.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.register({
      secret: JWT_SECRET,
      signOptions: { expiresIn: '24h' }, // Token válido por 24 horas
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [JwtModule],
})
export class AuthModule {}
```

---

## Parte 7: Controlador de Autenticación

### Paso 7.1: Implementar endpoints

Editar `src/auth/auth.controller.ts`:

```typescript
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
  constructor(private readonly authService: AuthService) {}

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
    return {
      message: 'Perfil obtenido exitosamente',
      user: req.user,
    };
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
```

---

## 🧪 Parte 8: Pruebas con Postman

### Paso 8.1: Configuración Inicial de Postman

#### Crear una Colección

1. Abrir Postman
2. Click en **"Collections"** (panel izquierdo)
3. Click en **"+"** o **"New Collection"**
4. Nombre: `Auth Taller NestJS`
5. Click en **"Create"**

#### Crear Variable de Entorno para el Token

1. Click en **"Environments"** (panel izquierdo)
2. Click en **"+"** para crear nuevo entorno
3. Nombre del entorno: `Local Dev`
4. Agregar variables:

| Variable | Initial Value | Current Value |
|----------|---------------|---------------|
| `base_url` | `http://localhost:3000` | `http://localhost:3000` |
| `token` | (dejar vacío) | (dejar vacío) |

5. Click en **"Save"**
6. Seleccionar el entorno `Local Dev` en el dropdown superior derecho

---

### Paso 8.2: Probar Registro de Usuario

#### Crear Request de Registro

1. Click derecho en la colección `Auth Taller NestJS`
2. Seleccionar **"Add request"**
3. Nombre: `01 - Registro`

#### Configurar el Request

**Pestaña Principal:**
```
Método: POST
URL: {{base_url}}/auth/register
```

**Pestaña "Headers":**
| Key | Value |
|-----|-------|
| Content-Type | application/json |

**Pestaña "Body":**
1. Seleccionar **"raw"**
2. Seleccionar **"JSON"** en el dropdown
3. Escribir el siguiente JSON:
```json
{
    "nombre": "Juan Pérez",
    "email": "juan@test.com",
    "password": "miPassword123"
}
```

#### Enviar y Verificar

1. Click en **"Send"**
2. **Respuesta esperada (Status 201 Created):**
```json
{
    "message": "Usuario registrado exitosamente",
    "user": {
        "id": 1,
        "nombre": "Juan Pérez",
        "email": "juan@test.com",
        "createdAt": "2024-01-15T10:30:00.000Z"
    }
}
```

---

### Paso 8.3: Probar Validaciones del Registro

#### Crear Request para Email Inválido

1. Duplicar el request `01 - Registro` (click derecho → Duplicate)
2. Renombrar a: `02 - Registro (Email Inválido)`
3. Modificar el Body:
```json
{
    "nombre": "Test Usuario",
    "email": "esto-no-es-email",
    "password": "123456"
}
```

4. Click en **"Send"**
5. **Respuesta esperada (Status 400 Bad Request):**
```json
{
    "statusCode": 400,
    "message": ["Debe proporcionar un email válido"],
    "error": "Bad Request"
}
```

#### Crear Request para Password Corto

1. Duplicar el request `01 - Registro`
2. Renombrar a: `03 - Registro (Password Corto)`
3. Modificar el Body:
```json
{
    "nombre": "Test Usuario",
    "email": "test@test.com",
    "password": "123"
}
```

4. Click en **"Send"**
5. **Respuesta esperada (Status 400 Bad Request):**
```json
{
    "statusCode": 400,
    "message": ["La contraseña debe tener al menos 6 caracteres"],
    "error": "Bad Request"
}
```

#### Crear Request para Email Duplicado

1. Duplicar el request `01 - Registro`
2. Renombrar a: `04 - Registro (Email Duplicado)`
3. Usar el mismo email que ya registraste:
```json
{
    "nombre": "Otro Usuario",
    "email": "juan@test.com",
    "password": "password123"
}
```

4. Click en **"Send"**
5. **Respuesta esperada (Status 409 Conflict):**
```json
{
    "statusCode": 409,
    "message": "El email ya está registrado",
    "error": "Conflict"
}
```

---

### Paso 8.4: Probar Login

#### Crear Request de Login

1. Click derecho en la colección → **"Add request"**
2. Nombre: `05 - Login`

#### Configurar el Request

**Pestaña Principal:**
```
Método: POST
URL: {{base_url}}/auth/login
```

**Pestaña "Headers":**
| Key | Value |
|-----|-------|
| Content-Type | application/json |

**Pestaña "Body":**
```json
{
    "email": "juan@test.com",
    "password": "miPassword123"
}
```

#### Guardar Token Automáticamente

**Pestaña "Tests"** (muy importante):
```javascript
// Este script se ejecuta DESPUÉS de recibir la respuesta
// Extrae el token y lo guarda en la variable de entorno

// Verificar que la respuesta sea exitosa
if (pm.response.code === 201 || pm.response.code === 200) {
    // Parsear el body de la respuesta
    var jsonData = pm.response.json();
    
    // Guardar el token en la variable de entorno
    pm.environment.set("token", jsonData.access_token);
    
    // Mostrar mensaje en consola
    console.log("✅ Token guardado exitosamente");
    console.log("Token: " + jsonData.access_token.substring(0, 50) + "...");
}
```

#### Enviar y Verificar

1. Click en **"Send"**
2. **Respuesta esperada (Status 201 Created):**
```json
{
    "message": "Login exitoso",
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": 1,
        "nombre": "Juan Pérez",
        "email": "juan@test.com"
    }
}
```

3. **Verificar que el token se guardó:**
   - Click en el ícono de **"Environment quick look"** (ojo) arriba a la derecha
   - Debe aparecer la variable `token` con el valor del JWT

---

### Paso 8.5: Probar Login con Credenciales Incorrectas

#### Crear Request para Password Incorrecto

1. Duplicar el request `05 - Login`
2. Renombrar a: `06 - Login (Password Incorrecto)`
3. Modificar el Body:
```json
{
    "email": "juan@test.com",
    "password": "contraseñaEquivocada"
}
```

4. **Eliminar el script de la pestaña "Tests"** (para no sobreescribir el token válido)
5. Click en **"Send"**
6. **Respuesta esperada (Status 401 Unauthorized):**
```json
{
    "statusCode": 401,
    "message": "Credenciales inválidas",
    "error": "Unauthorized"
}
```

#### Crear Request para Usuario No Existente

1. Duplicar el request `05 - Login`
2. Renombrar a: `07 - Login (Usuario No Existe)`
3. Modificar el Body:
```json
{
    "email": "noexiste@test.com",
    "password": "cualquierPassword"
}
```

4. **Eliminar el script de la pestaña "Tests"**
5. Click en **"Send"**
6. **Respuesta esperada (Status 401 Unauthorized):**
```json
{
    "statusCode": 401,
    "message": "Credenciales inválidas",
    "error": "Unauthorized"
}
```

---

### Paso 8.6: Probar Ruta Protegida SIN Token

#### Crear Request de Profile sin Autenticación

1. Click derecho en la colección → **"Add request"**
2. Nombre: `08 - Profile (Sin Token)`

#### Configurar el Request

**Pestaña Principal:**
```
Método: GET
URL: {{base_url}}/auth/profile
```

**NO agregar ningún header de Authorization**

#### Enviar y Verificar

1. Click en **"Send"**
2. **Respuesta esperada (Status 401 Unauthorized):**
```json
{
    "statusCode": 401,
    "message": "Unauthorized"
}
```

---

### Paso 8.7: Probar Ruta Protegida CON Token

#### Crear Request de Profile con Autenticación

1. Click derecho en la colección → **"Add request"**
2. Nombre: `09 - Profile (Con Token)`

#### Configurar el Request

**Pestaña Principal:**
```
Método: GET
URL: {{base_url}}/auth/profile
```

**Pestaña "Authorization":**
1. Type: **Bearer Token**
2. Token: `{{token}}`

> **Nota:** Usamos `{{token}}` que es la variable guardada automáticamente en el login

#### Enviar y Verificar

1. Click en **"Send"**
2. **Respuesta esperada (Status 200 OK):**
```json
{
    "message": "Perfil obtenido exitosamente",
    "user": {
        "userId": 1,
        "email": "juan@test.com",
        "nombre": "Juan Pérez"
    }
}
```

---

### Paso 8.8: Probar Ruta Protegida con Token Inválido

#### Crear Request con Token Manipulado

1. Duplicar el request `09 - Profile (Con Token)`
2. Renombrar a: `10 - Profile (Token Inválido)`

**Pestaña "Authorization":**
1. Type: **Bearer Token**
2. Token: `token_falso_inventado_12345`

#### Enviar y Verificar

1. Click en **"Send"**
2. **Respuesta esperada (Status 401 Unauthorized):**
```json
{
    "statusCode": 401,
    "message": "Token inválido o expirado",
    "error": "Unauthorized"
}
```

---

### Paso 8.9: Probar otra Ruta Protegida

#### Crear Request para Ruta Protected

1. Click derecho en la colección → **"Add request"**
2. Nombre: `11 - Ruta Protegida`

#### Configurar el Request

**Pestaña Principal:**
```
Método: GET
URL: {{base_url}}/auth/protected
```

**Pestaña "Authorization":**
1. Type: **Bearer Token**
2. Token: `{{token}}`

#### Enviar y Verificar

1. Click en **"Send"**
2. **Respuesta esperada (Status 200 OK):**
```json
{
    "message": "¡Hola Juan Pérez! Esta es una ruta protegida.",
    "timestamp": "2024-01-15T10:45:00.000Z",
    "userId": 1
}
```

---

## 📋 Resumen de Requests en la Colección

| # | Nombre | Método | URL | Resultado Esperado |
|---|--------|--------|-----|-------------------|
| 01 | Registro | POST | /auth/register | 201 - Usuario creado |
| 02 | Registro (Email Inválido) | POST | /auth/register | 400 - Validación |
| 03 | Registro (Password Corto) | POST | /auth/register | 400 - Validación |
| 04 | Registro (Email Duplicado) | POST | /auth/register | 409 - Conflict |
| 05 | Login | POST | /auth/login | 201 - Token generado |
| 06 | Login (Password Incorrecto) | POST | /auth/login | 401 - Unauthorized |
| 07 | Login (Usuario No Existe) | POST | /auth/login | 401 - Unauthorized |
| 08 | Profile (Sin Token) | GET | /auth/profile | 401 - Unauthorized |
| 09 | Profile (Con Token) | GET | /auth/profile | 200 - Datos usuario |
| 10 | Profile (Token Inválido) | GET | /auth/profile | 401 - Unauthorized |
| 11 | Ruta Protegida | GET | /auth/protected | 200 - Mensaje personalizado |

---

## 🔍 Verificar Token en jwt.io

1. Después de hacer login, copiar el `access_token` de la respuesta
2. Ir a [jwt.io](https://jwt.io)
3. Pegar el token en el campo **"Encoded"** (izquierda)
4. Verificar en **"Decoded"** (derecha):

**Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": 1,
  "email": "juan@test.com",
  "nombre": "Juan Pérez",
  "iat": 1705312200,
  "exp": 1705398600
}
```

5. En la sección **"Verify Signature"**, escribir el secreto:
```
   mi_clave_secreta_muy_segura_2024
```
6. Debe aparecer: **"Signature Verified"** ✅

---

## 💡 Tips de Postman

### Atajo para duplicar requests
- **Windows/Linux:** `Ctrl + D`
- **Mac:** `Cmd + D`

### Ver la consola de Postman
- **Windows/Linux:** `Ctrl + Alt + C`
- **Mac:** `Cmd + Option + C`

### Ejecutar toda la colección
1. Click en los tres puntos de la colección
2. Seleccionar **"Run collection"**
3. Esto ejecuta todos los requests en orden

### Exportar la colección
1. Click derecho en la colección
2. Seleccionar **"Export"**
3. Guardar como JSON para compartir con compañeros
---

## Estructura Final del Proyecto

```
src/
├── auth/
│   ├── dto/
│   │   ├── register.dto.ts      ← Validación de registro
│   │   └── login.dto.ts         ← Validación de login
│   ├── guards/
│   │   └── jwt-auth.guard.ts    ← Protege rutas
│   ├── strategies/
│   │   └── jwt.strategy.ts      ← Valida tokens
│   ├── auth.controller.ts       ← Endpoints
│   ├── auth.module.ts           ← Configuración
│   └── auth.service.ts          ← Lógica de negocio
├── users/
│   ├── entities/
│   │   └── user.entity.ts       ← Modelo de usuario
│   ├── users.controller.ts
│   ├── users.module.ts
│   └── users.service.ts         ← CRUD de usuarios
├── app.module.ts
└── main.ts                      ← Configuración global
```

---

## Checklist de Entregables

Antes de entregar, verifica que tu proyecto cumpla con:

| # | Requisito | Verificación |
|---|-----------|--------------|
| 1 | Registro funciona con validaciones | `POST /auth/register` |
| 2 | No permite emails duplicados | Error 409 Conflict |
| 3 | Contraseñas se guardan hasheadas | Nunca en texto plano |
| 4 | Login retorna token JWT | `POST /auth/login` |
| 5 | Token contiene datos del usuario | Verificar en jwt.io |
| 6 | Ruta protegida rechaza sin token | Error 401 |
| 7 | Ruta protegida funciona con token | `GET /auth/profile` |
| 8 | `req.user` contiene datos correctos | userId, email, nombre |

---

## 🔍 Verificar tu Token

1. Copia el `access_token` del login
2. Ve a [jwt.io](https://jwt.io)
3. Pega el token en el campo "Encoded"
4. Verifica que el payload contenga:
   - `sub`: ID del usuario
   - `email`: Email del usuario
   - `nombre`: Nombre del usuario
   - `iat`: Fecha de emisión
   - `exp`: Fecha de expiración

---

## Errores Comunes y Soluciones

### Error: "Cannot find module 'bcrypt'"
```bash
npm install bcrypt
npm install -D @types/bcrypt
```

### Error: "Unauthorized" con token correcto
- Verifica que el header sea exactamente: `Authorization: Bearer <token>`
- Sin espacios extra antes o después del token
- El token no debe tener comillas

### Error: "SECRET_KEY must be provided"
- Verifica que `JWT_SECRET` esté definido en `jwt.strategy.ts`
- Verifica que sea el mismo valor en `auth.module.ts`

### El Guard no funciona
- Verifica que `JwtStrategy` esté en `providers` de `AuthModule`
- Verifica que `PassportModule` esté en `imports` de `AuthModule`

---

## Recursos Adicionales

- [Documentación NestJS - Authentication](https://docs.nestjs.com/security/authentication)
- [JWT.io - Debugger](https://jwt.io)
- [bcrypt en npm](https://www.npmjs.com/package/bcrypt)

---

## Reto Adicional (Opcional)

Si terminaste antes, intenta implementar:

1. **Endpoint para cambiar contraseña** (requiere autenticación)
2. **Roles de usuario** (admin, cliente, vendedor)
3. **Guard de roles** que verifique si el usuario tiene permiso

---
