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