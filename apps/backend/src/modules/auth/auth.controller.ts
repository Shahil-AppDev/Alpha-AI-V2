import { Controller, Post, Get, Body, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('api/auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() body: { email: string; password: string; name: string }) {
    return this.authService.register(body.email, body.password, body.name);
  }

  @Post('login')
  async login(@Body() body: { email: string; password: string }) {
    return this.authService.login(body.email, body.password);
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  getProfile(@Request() req) {
    return req.user;
  }

  @Get('validate')
  @UseGuards(JwtAuthGuard)
  validateToken(@Request() req) {
    return {
      id: req.user.userId || req.user.id,
      email: req.user.email,
      name: req.user.name || req.user.username,
      role: req.user.role || 'user',
      permissions: req.user.role === 'admin' ? ['*'] : []
    };
  }
}
