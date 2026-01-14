/**
 * ==============================================
 * ENTIDAD DE USUARIO
 * ==============================================
 * Representa la estructura de un usuario en el sistema.
 * Esta clase define todas las propiedades que un usuario
 * puede tener en la base de datos.
 * 
 * NOTA: Cuando integres TypeORM, agrega los decoradores
 * @Entity(), @Column(), @PrimaryGeneratedColumn(), etc.
 */

export class User {
    // ============================================
    // IDENTIFICADOR ÚNICO
    // ============================================
    /**
     * ID único del usuario (clave primaria)
     * - Se genera automáticamente al crear el usuario
     * - Es inmutable una vez asignado
     * - Se usa para referencias en otras tablas
     * 
     * TypeORM: @PrimaryGeneratedColumn()
     */
    id: number;

    // ============================================
    // INFORMACIÓN PERSONAL
    // ============================================
    /**
     * Nombre completo del usuario
     * - Requerido en el registro
     * - Longitud mínima: 2 caracteres
     * - Longitud máxima: 100 caracteres
     * 
     * TypeORM: @Column({ type: 'varchar', length: 100 })
     */
    nombre: string;

    /**
     * Dirección de correo electrónico
     * - Debe ser único en todo el sistema
     * - Se usa como identificador para login
     * - Formato validado (debe contener @)
     * 
     * TypeORM: @Column({ type: 'varchar', length: 255, unique: true })
     */
    email: string;

    // ============================================
    // SEGURIDAD
    // ============================================
    /**
     * Contraseña hasheada del usuario
     * - NUNCA se almacena en texto plano
     * - Se hashea con bcrypt antes de guardar
     * - Mínimo 6 caracteres antes del hash
     * - El hash resultante tiene ~60 caracteres
     * 
     * IMPORTANTE: Nunca incluir en respuestas al cliente
     * 
     * TypeORM: @Column({ type: 'varchar', length: 255, select: false })
     * El select: false evita que se incluya en consultas por defecto
     */
    password: string;

    // ============================================
    // ESTADO DE LA CUENTA
    // ============================================
    /**
     * Indica si la cuenta del usuario está activa
     * - true: Usuario puede iniciar sesión
     * - false: Usuario bloqueado/desactivado
     * - Por defecto es true al registrarse
     * 
     * Útil para:
     * - Bloquear usuarios sin eliminarlos
     * - Desactivar cuentas temporalmente
     * - Implementar verificación de email
     * 
     * TypeORM: @Column({ type: 'boolean', default: true })
     */
    isActive: boolean;

    // ============================================
    // ROLES Y PERMISOS (Opcional - para expansión)
    // ============================================
    /**
     * Rol del usuario en el sistema
     * - Define los permisos y acceso a recursos
     * - Valores comunes: 'user', 'admin', 'moderator'
     * - Por defecto es 'user' al registrarse
     * 
     * TypeORM: @Column({ type: 'varchar', length: 20, default: 'user' })
     */
    role: string;

    // ============================================
    // AUDITORÍA Y TIMESTAMPS
    // ============================================
    /**
     * Fecha y hora de creación de la cuenta
     * - Se asigna automáticamente al crear el usuario
     * - Formato: ISO 8601 (ej: 2024-01-15T10:30:00.000Z)
     * - Inmutable una vez creado
     * 
     * TypeORM: @CreateDateColumn()
     */
    createdAt: Date;

    /**
     * Fecha y hora de la última actualización
     * - Se actualiza automáticamente en cada modificación
     * - Útil para tracking de cambios
     * 
     * TypeORM: @UpdateDateColumn()
     */
    updatedAt?: Date;

    /**
     * Fecha y hora del último inicio de sesión
     * - Se actualiza cada vez que el usuario hace login
     * - Útil para detectar cuentas inactivas
     * - Puede ser null si nunca ha iniciado sesión
     * 
     * TypeORM: @Column({ type: 'timestamp', nullable: true })
     */
    lastLoginAt?: Date;
}

// ============================================
// TIPO PARA RESPUESTAS SIN PASSWORD
// ============================================
/**
 * Tipo que excluye la contraseña del usuario
 * Usar este tipo cuando se retornan datos al cliente
 * para evitar exponer información sensible
 */
export type UserWithoutPassword = Omit<User, 'password'>;

// ============================================
// TIPO PARA CREACIÓN DE USUARIO
// ============================================
/**
 * Tipo para crear un nuevo usuario
 * Excluye campos que se generan automáticamente
 */
export type CreateUserData = Omit<User, 'id' | 'createdAt' | 'updatedAt' | 'lastLoginAt' | 'isActive' | 'role'>;
