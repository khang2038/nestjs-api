import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}
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
    delete user.hash;
    return user;
  }
}
