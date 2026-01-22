import { Module } from '@nestjs/common';
import { ToolsRegistryController } from './tools-registry.controller';
import { ToolsRegistryService } from './tools-registry.service';

@Module({
  controllers: [ToolsRegistryController],
  providers: [ToolsRegistryService],
  exports: [ToolsRegistryService],
})
export class ToolsRegistryModule {}
