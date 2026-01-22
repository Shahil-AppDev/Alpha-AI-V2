# Frontend Deployment Guide

## Overview

This guide covers the deployment of the Alpha AI Security Orchestrator frontend application. The frontend is built with Next.js 14, React 18, TypeScript, and Tailwind CSS.

## Prerequisites

- Node.js 18+ 
- npm or yarn
- PowerShell (for Windows deployment script)
- Docker (optional, for containerized deployment)

## Quick Start

### Local Development

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

### Production Deployment

#### Using PowerShell Script (Windows)

```powershell
# Deploy to production
.\deploy-frontend.ps1 -Environment production

# Deploy to staging
.\deploy-frontend.ps1 -Environment staging

# Skip tests and build (for quick deployments)
.\deploy-frontend.ps1 -SkipTests -SkipBuild
```

#### Manual Deployment

```bash
# Install dependencies
npm ci

# Run tests
npm run test

# Build application
npm run build

# The built application is in the .next directory
```

## Deployment Options

### 1. Static Site Hosting (Vercel/Netlify)

The application is optimized for static hosting:

```bash
# Export static files
npm run export

# Deploy to Vercel
npx vercel --prod

# Deploy to Netlify
npx netlify deploy --prod --dir=.next
```

### 2. Docker Deployment

```dockerfile
# Dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:18-alpine AS runner
WORKDIR /app
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json
EXPOSE 3000
CMD ["npm", "start"]
```

```bash
# Build and run
docker build -t alpha-ai-frontend .
docker run -p 3000:3000 alpha-ai-frontend
```

### 3. Traditional Web Server

After building, copy the `.next` directory to your web server and configure it to serve Node.js applications.

## Environment Variables

Create a `.env.local` file for environment-specific configuration:

```env
# API Configuration
NEXT_PUBLIC_API_URL=https://your-api.com
NEXT_PUBLIC_WS_URL=wss://your-api.com/ws

# Authentication
NEXT_PUBLIC_AUTH_ENABLED=true
NEXT_PUBLIC_AUTH_URL=https://your-auth.com

# Feature Flags
NEXT_PUBLIC_ENABLE_ANALYTICS=true
NEXT_PUBLIC_ENABLE_DEBUG=false

# Security
NEXT_PUBLIC_CSP_ENABLED=true
NEXT_PUBLIC_SECURITY_HEADERS=true
```

## Build Optimization

### Automatic Optimizations

The build process includes:
- Code splitting
- Tree shaking
- Image optimization
- Font optimization
- Bundle analysis

### Manual Optimization

```bash
# Analyze bundle size
npm run analyze

# Optimize images
npm run optimize-images

# Generate sitemap
npm run generate-sitemap
```

## Security Considerations

### Content Security Policy

Configure CSP headers in your hosting environment:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https: wss:;
```

### HTTPS Enforcement

Ensure HTTPS is enabled in production:

```javascript
// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains',
          },
        ],
      },
    ];
  },
};
```

## Monitoring and Analytics

### Application Monitoring

```javascript
// Add monitoring in _app.js
import { analytics } from '@/lib/analytics';

function MyApp({ Component, pageProps }) {
  useEffect(() => {
    analytics.track('page_view');
  }, []);
  
  return <Component {...pageProps} />;
}
```

### Performance Monitoring

```bash
# Lighthouse CI
npm install -g @lhci/cli
lhci autorun
```

## Troubleshooting

### Common Issues

1. **Build Failures**
   ```bash
   # Clear build cache
   rm -rf .next
   npm run build
   ```

2. **Memory Issues**
   ```bash
   # Increase Node.js memory limit
   NODE_OPTIONS="--max-old-space-size=4096" npm run build
   ```

3. **Environment Variables**
   ```bash
   # Verify environment variables
   npm run build:debug
   ```

### Debug Mode

Enable debug mode for detailed build information:

```bash
DEBUG=* npm run build
```

## Rollback Procedures

### Quick Rollback

```bash
# Restore previous version
git checkout HEAD~1
npm run build
npm start
```

### Blue-Green Deployment

Maintain two production environments and switch traffic between them:

```bash
# Deploy to green environment
./deploy-frontend.ps1 -Environment production-green

# Switch traffic to green
# (Configure in your load balancer)
```

## Performance Optimization

### Caching Strategy

```javascript
// next.config.js
module.exports = {
  async rewrites() {
    return [
      {
        source: '/static/:path*',
        destination: '/_next/static/:path*',
      },
    ];
  },
};
```

### CDN Configuration

Configure your CDN to cache:
- Static assets (/.next/static/*)
- Images (/images/*)
- Fonts (/fonts/*)

## Maintenance

### Regular Updates

```bash
# Update dependencies
npm update

# Security audit
npm audit
npm audit fix
```

### Health Checks

Monitor application health:

```javascript
// pages/api/health.js
export default function handler(req, res) {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version,
  });
}
```

## Support

For deployment issues:
1. Check the build logs
2. Verify environment variables
3. Test with a clean build
4. Review the troubleshooting section above

## Additional Resources

- [Next.js Deployment Documentation](https://nextjs.org/docs/deployment)
- [Vercel Deployment Guide](https://vercel.com/docs/concepts/deployments)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Web Security Guidelines](https://owasp.org/www-project-secure-headers/)
