import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Alpha AI Backend API - AI-driven Offensive Security Platform';
  }
}
