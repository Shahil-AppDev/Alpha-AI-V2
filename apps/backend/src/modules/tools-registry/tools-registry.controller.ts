import { Body, Controller, Delete, Get, Param, Post, Query } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { ToolsRegistryService } from './tools-registry.service';

@ApiTags('tools')
@Controller('tools')
export class ToolsRegistryController {
  constructor(private readonly toolsRegistryService: ToolsRegistryService) {}

  @Get()
  @ApiOperation({ summary: 'Get all tools' })
  @ApiResponse({ status: 200, description: 'Returns all registered tools' })
  async findAll(@Query('category') category?: string) {
    return this.toolsRegistryService.findAll({ category });
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get tool by ID' })
  @ApiResponse({ status: 200, description: 'Returns a specific tool' })
  @ApiResponse({ status: 404, description: 'Tool not found' })
  async findOne(@Param('id') id: string) {
    return this.toolsRegistryService.findOne(id);
  }

  @Post()
  @ApiOperation({ summary: 'Create a new tool' })
  @ApiResponse({ status: 201, description: 'Tool created successfully' })
  async create(@Body() createToolDto: any) {
    return this.toolsRegistryService.create(createToolDto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a tool' })
  @ApiResponse({ status: 200, description: 'Tool deleted successfully' })
  @ApiResponse({ status: 404, description: 'Tool not found' })
  async remove(@Param('id') id: string) {
    return this.toolsRegistryService.remove(id);
  }
}
