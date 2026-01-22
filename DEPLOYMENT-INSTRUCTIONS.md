# Deployment Instructions

## SSH Keys Generated

**Private Key:** `github-actions-key` (add to GitHub Secrets)
**Public Key:** `github-actions-key.pub` (add to server)

## GitHub Secrets Setup

Go to your GitHub repository → Settings → Secrets and variables → Actions → New repository secret

Add these secrets:

1. **SSH_PRIVATE_KEY**
   - Copy the contents of `github-actions-key` file
   - ```
     -----BEGIN OPENSSH PRIVATE KEY-----
     b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
     NhAAAAAwEAAQAAAIEAy1cb2SWpNWhiJERy3YWqlRRZtkRgO57i69X54yGY3Xr14GC4iSe
     UFcBdXs85l3i6jsEC6F7ugISyHX075jA/cAZc0CNtRak6GzMitBndbgI3eEHxC9B6TKCwT
     I0j+bZu2uGGaM3uiQq1bjpEfTKAw2tGy8oeEzHPanx2Z8TKex0RmALiJRMAyMveTDdTzy
     dHAsw0S6CwziPRueopaeJ4syRvrwacU2O8oo4VjzBEtK4zCKHvWnC2KlRKFZxL1/BnJmV
     ERl0kMubGhXSqj2nrLRChCAM5ZJuvFlLp8G/HjIpvFVuuxe2Fbhfq4kpNVzaySvaGa66t
     AHLgcYq0bgmEfmUOWCcccBGRGBGy3kfSZgwwAB+DQbLuz2GWhnaNlFsGO/7nI4zf1bM0cw
     ohcBKVYbOiiipyIGiHGsRkWKG/8zFV6oA9RPuXOy+MFq+Gdp/KhetdmXOZp/fYAc7swC/1
     JcCQE tHmvWVcTFQI62soGu5QwJEU6ucee2HnE89s3ht028u/j321EfbxNPqbXgdDjNEBT
     TDQihAlkQ7jIe1cYnxA95SkYFABriwgGzIOdgCBoABaaA6cmTxroToTlLrXW+6DQ2fwfjr
     2tYmGz7bu16QVzrTadbsMyy3JbClURmhTVm6/Hq5VycRWe5l+9j2qdmKUe62s8TSkiw7cz
     l6i068AAAALGdpdGh1Yi1hY3Rpb25zQGFscGhhLWFpAQIDBAUGBw==
     -----END OPENSSH PRIVATE KEY-----
     ```

2. **SERVER_HOST**
   - Value: `157.180.107.154`

3. **SERVER_USER**
   - Value: `root`

## Server Setup

### 1. Add SSH Public Key to Server

Connect to your server and add the public key:

```bash
ssh root@157.180.107.154

# Add the public key to authorized_keys
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDLVxvZJak1eaIkRHLdhaqVFFm2RGA7nuLr1fnjIZjdevXgYLiJJ5QVwF1ezzmXeLqOwQLoXu6AhLIdfTvmMD9wBlzQI21FqTobMyK0Gd1uAjd4QfEL0HpMoLBMjSP5tk7Y4YZoze6JCrVuOkR9MoDDa0bLyh4TMc9qfHZnxMp7HRGYAuIlEwDIy95MN1PPJ0ewLCtLoLDI9G56ilp4nizJG+vBpxTY7yirhWNvES0rjMIIoe9acLYqVEoVnEvX8GcmZURGXSYy5saFdKqPaestEKEoAw9km68WUunwb8eMim8VW66F7YVuF+riSk1XNpLK9oZrrq0AcuBxirRuCYR+ZQ5YJxxwEZEYZrLeR9JmDATAH4NBsu7PYZaGdo2UWwY7/ucjjN/XszRzCiFwEpVhs6KKKnIgaIcaxGRYob/zMVXqgD1E+5c7L4wWr4Z2n8qF612Zc5mn99gBzuzAL/UlwJAS0ea9pVxMVAjrayga7lDAkRTq5x57YecTz2zeG3Tby5+PfbUR9vE0+pteB0OM0QFNMNCKECWRDuMh7VxifED3lKRgUAGuLCAbMg52AIGgAFpoDpyZPGuhOhOUtetb7oNDZ/B+Ova1iYbPtu7XpBXOtNpp2wzLLclsKVRGaFNWbr8erlXJxFZ7mX72Pap2YpR7razxNKSLDtzOXqLTrw== github-actions@alpha-ai" >> ~/.ssh/authorized_keys

# Set proper permissions
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

### 2. Run Server Setup Workflow

1. Go to your GitHub repository → Actions
2. Select "Setup Server" workflow
3. Click "Run workflow"
4. Use default settings (setup nginx, node, pm2)

## Deployment Workflows

### Automatic Deployment
- **Frontend**: Triggers on push to `main` branch when `frontend/**` files change
- **Backend**: Triggers on push to `main` branch when `apps/backend/**`, `src/**`, or `package.json` change

### Manual Deployment
1. Go to Actions tab in GitHub
2. Select the desired workflow (Deploy Frontend/Backend)
3. Click "Run workflow"

## Server Structure After Deployment

```
/var/www/alpha-ai/
├── frontend/          # Built Next.js frontend files
├── backend/           # NestJS backend application
└── logs/              # Application logs
```

## Services Running

- **Nginx**: Port 80/443 (Reverse proxy)
- **Backend**: Port 3001 (NestJS app via PM2)
- **Firewall**: Configured with UFW

## Monitoring

Check PM2 status:
```bash
ssh root@157.180.107.154 "pm2 status"
```

Check logs:
```bash
ssh root@157.180.107.154 "pm2 logs alpha-ai-backend"
```

## SSL/HTTPS Setup (Optional)

After deployment, you can add SSL using Let's Encrypt:

```bash
ssh root@157.180.107.154 "
apt install certbot python3-certbot-nginx
certbot --nginx -d your-domain.com
"
```
