import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt/dist';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService
  ) {}
  async signup(dto: AuthDto) {
    const hash = await argon.hash(dto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      delete user.hash;
      return user;
    } catch (error) {
      throw new ForbiddenException('Credentials taken');
    }
  }

  async signin(dto: AuthDto) {
    const user = await this.prisma.user.findFirstOrThrow({
      where: {
        email: dto.email,
      },
    });
    const match = await argon.verify(user.hash, dto.password);
    if (!match) {
      throw new ForbiddenException();
    }
    const token = await this.signToken(user.id, user.email);
    console.log(token);
    return token;
  }

  async signToken(userId: number, email: string) {
    const payload = {
      sub: userId,
      email: email,
    };
    return {
      access_token: await this.jwt.signAsync(payload, {
        expiresIn: '15m',
        secret: this.config.get('JWT_SECRET'),
      }),
    };
  }
}
