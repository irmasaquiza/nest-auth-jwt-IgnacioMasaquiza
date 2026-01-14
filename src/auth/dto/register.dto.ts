import { IsEmail, IsString, MinLength, MaxLength } from 'class-validator';

export class RegisterDto {
    @IsString()
    @MinLength(3)
    @MaxLength(50)
    name: string;

    @IsString()
    @MinLength(3)
    @MaxLength(50)
    lastName: string;

    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    password: string;
}