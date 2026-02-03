import { Module } from '@nestjs/common';
import { OpenClawService } from './openclaw.service';
import { OpenClawController } from './openclaw.controller';
import { OpenClawGateway } from './openclaw.gateway';

@Module({
  controllers: [OpenClawController],
  providers: [OpenClawService, OpenClawGateway],
  exports: [OpenClawService],
})
export class OpenClawModule {}
