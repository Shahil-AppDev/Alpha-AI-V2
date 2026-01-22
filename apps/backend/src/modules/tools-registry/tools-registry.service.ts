import { BadRequestException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { Prisma, RiskLevel, Tool, ToolLanguage } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';

interface CreateToolDto {
  name: string;
  description: string;
  category: string;
  language: ToolLanguage;
  riskLevel: RiskLevel;
  code: string;
  parameters?: any;
  enabled?: boolean;
}

@Injectable()
export class ToolsRegistryService {
  private readonly logger = new Logger(ToolsRegistryService.name);

  constructor(private prisma: PrismaService) {}

  async create(createToolDto: CreateToolDto): Promise<Tool> {
    try {
      const tool = await this.prisma.tool.create({
        data: {
          name: createToolDto.name,
          description: createToolDto.description,
          category: createToolDto.category,
          language: createToolDto.language,
          riskLevel: createToolDto.riskLevel,
          code: createToolDto.code,
          parameters: createToolDto.parameters || {},
        },
      });

      this.logger.log(`Tool created: ${tool.name} (${tool.id})`);
      return tool;
    } catch (error: any) {
      if (error.code === 'P2002') {
        throw new BadRequestException(`Tool with name '${createToolDto.name}' already exists`);
      }
      throw error;
    }
  }

  async findAll(filters?: {
    category?: string;
    riskLevel?: RiskLevel;
    language?: ToolLanguage;
  }): Promise<Tool[]> {
    const where: Prisma.ToolWhereInput = {};

    if (filters?.category) {
      where.category = filters.category;
    }

    if (filters?.riskLevel) {
      where.riskLevel = filters.riskLevel;
    }

    if (filters?.language) {
      where.language = filters.language;
    }

    return this.prisma.tool.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });
  }

  async findOne(id: string): Promise<Tool> {
    const tool = await this.prisma.tool.findUnique({
      where: { id },
    });

    if (!tool) {
      throw new NotFoundException(`Tool with ID '${id}' not found`);
    }

    return tool;
  }

  async findByName(name: string): Promise<Tool | null> {
    return this.prisma.tool.findUnique({
      where: { name },
    });
  }

  async update(id: string, updateData: Partial<CreateToolDto>): Promise<Tool> {
    try {
      const tool = await this.prisma.tool.update({
        where: { id },
        data: updateData,
      });

      this.logger.log(`Tool updated: ${tool.name} (${tool.id})`);
      return tool;
    } catch (error: any) {
      if (error.code === 'P2025') {
        throw new NotFoundException(`Tool with ID '${id}' not found`);
      }
      throw error;
    }
  }

  async remove(id: string): Promise<Tool> {
    try {
      const tool = await this.prisma.tool.delete({
        where: { id },
      });

      this.logger.log(`Tool deleted: ${tool.name} (${tool.id})`);
      return tool;
    } catch (error: any) {
      if (error.code === 'P2025') {
        throw new NotFoundException(`Tool with ID '${id}' not found`);
      }
      throw error;
    }
  }

  async toggleEnabled(id: string): Promise<Tool> {
    const tool = await this.findOne(id);
    const updateData = { enabled: !tool.enabled };
    return this.prisma.tool.update({
      where: { id },
      data: updateData,
    });
  }

  async getToolsByCategory(): Promise<Record<string, Tool[]>> {
    const tools = await this.findAll();
    
    return tools.reduce((acc, tool) => {
      if (!acc[tool.category]) {
        acc[tool.category] = [];
      }
      acc[tool.category].push(tool);
      return acc;
    }, {} as Record<string, Tool[]>);
  }
}
