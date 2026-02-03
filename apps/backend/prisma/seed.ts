import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Seeding database...');

  // Créer utilisateur admin
  const adminPassword = await bcrypt.hash('Admin@2026', 10);
  const admin = await prisma.user.upsert({
    where: { email: 'admin@qatar-one.app' },
    update: {},
    create: {
      email: 'admin@qatar-one.app',
      password: adminPassword,
      name: 'Administrator',
      role: 'admin',
    },
  });
  console.log('✅ Admin user created:', admin.email);

  // Créer utilisateur test
  const testPassword = await bcrypt.hash('Test@2026', 10);
  const testUser = await prisma.user.upsert({
    where: { email: 'test@qatar-one.app' },
    update: {},
    create: {
      email: 'test@qatar-one.app',
      password: testPassword,
      name: 'Test User',
      role: 'user',
    },
  });
  console.log('✅ Test user created:', testUser.email);

  console.log('🎉 Seeding completed!');
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
