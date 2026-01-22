#!/usr/bin/env pwsh

# Frontend Deployment Script for Alpha AI Security Orchestrator
# This script builds and deploys the frontend application

param(
    [string]$Environment = "production",
    [string]$BuildPath = ".",
    [string]$OutputPath = "./dist",
    [switch]$SkipBuild = $false,
    [switch]$SkipTests = $false,
    [switch]$Verbose = $false
)

# Color output functions
function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "🔄 $Message" -ForegroundColor Blue
}

# Check if we're in the correct directory
function Test-DeploymentEnvironment {
    Write-Step "Validating deployment environment..."
    
    if (-not (Test-Path "package.json")) {
        Write-Error "package.json not found. Please run this script from the frontend directory."
        exit 1
    }
    
    if (-not (Test-Path "next.config.js")) {
        Write-Error "next.config.js not found. This doesn't appear to be a Next.js project."
        exit 1
    }
    
    Write-Success "Environment validation passed"
}

# Install dependencies
function Install-Dependencies {
    Write-Step "Installing dependencies..."
    
    try {
        npm ci --production=false
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to install dependencies"
            exit 1
        }
        Write-Success "Dependencies installed successfully"
    }
    catch {
        Write-Error "Error installing dependencies: $_"
        exit 1
    }
}

# Run tests
function Start-ApplicationTests {
    if ($SkipTests) {
        Write-Warning "Skipping tests as requested"
        return
    }
    
    Write-Step "Running tests..."
    
    try {
        npm run test --if-present
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Tests failed"
            exit 1
        }
        Write-Success "All tests passed"
    }
    catch {
        Write-Warning "No tests found or test command failed: $_"
    }
}

# Build the application
function Start-ApplicationBuild {
    if ($SkipBuild) {
        Write-Warning "Skipping build as requested"
        return
    }
    
    Write-Step "Building application for $Environment environment..."
    
    try {
        $env:NODE_ENV = $Environment
        npm run build
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Build failed"
            exit 1
        }
        
        Write-Success "Application built successfully"
    }
    catch {
        Write-Error "Build failed: $_"
        exit 1
    }
}

# Optimize build output
function Optimize-Build {
    Write-Step "Optimizing build output..."
    
    try {
        # Check if .next directory exists
        if (-not (Test-Path ".next")) {
            Write-Error "Build output not found in .next directory"
            exit 1
        }
        
        # Compress static assets if gzip is available
        if (Get-Command gzip -ErrorAction SilentlyContinue) {
            Write-Info "Compressing static assets..."
            Get-ChildItem -Path ".next/static" -File -Recurse | ForEach-Object {
                gzip -c $_.FullName > "$($_.FullName).gz"
            }
        }
        
        Write-Success "Build optimization completed"
    }
    catch {
        Write-Warning "Build optimization failed: $_"
    }
}

# Generate deployment manifest
function New-DeploymentManifest {
    Write-Step "Generating deployment manifest..."
    
    try {
        $manifest = @{
            version     = (Get-Date -Format "yyyy-MM-dd-HH-mm-ss")
            environment = $Environment
            buildTime   = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            nodeVersion = (node --version)
            npmVersion  = (npm --version)
            nextVersion = (npm list next --json | ConvertFrom-Json).version
            files       = @()
        }
        
        # Add file list
        Get-ChildItem -Path ".next" -Recurse -File | ForEach-Object {
            $manifest.files += @{
                path = $_.FullName.Replace((Get-Location).Path, "")
                size = $_.Length
                hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
            }
        }
        
        $manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath ".next/deployment-manifest.json"
        Write-Success "Deployment manifest generated"
    }
    catch {
        Write-Warning "Failed to generate deployment manifest: $_"
    }
}

# Create deployment package
function New-DeploymentPackage {
    Write-Step "Creating deployment package..."
    
    try {
        $packageName = "alpha-ai-frontend-$Environment-$(Get-Date -Format 'yyyyMMdd-HHmmss').tar.gz"
        
        if (Get-Command tar -ErrorAction SilentlyContinue) {
            tar -czf $packageName .next/ public/ package.json next.config.js
        }
        else {
            Write-Warning "tar command not found, using PowerShell compression..."
            Compress-Archive -Path ".next/*", "public/*", "package.json", "next.config.js" -DestinationPath "$packageName.zip"
            $packageName = "$packageName.zip"
        }
        
        Write-Success "Deployment package created: $packageName"
        return $packageName
    }
    catch {
        Write-Error "Failed to create deployment package: $_"
        exit 1
    }
}

# Deploy to server (placeholder for actual deployment logic)
function Publish-ToServer {
    param([string]$PackagePath)
    
    Write-Step "Deploying to server..."
    
    # This is where you would add your actual deployment logic
    # Examples:
    # - Upload to AWS S3 + CloudFront
    # - Deploy to Vercel/Netlify
    # - Deploy to Docker container
    # - Deploy to traditional web server
    
    Write-Info "Deployment target: $Environment"
    Write-Info "Package: $PackagePath"
    
    # Example deployment commands (uncomment and modify as needed):
    
    # Vercel deployment
    # if (Get-Command vercel -ErrorAction SilentlyContinue) {
    #     vercel --prod
    # }
    
    # Docker deployment
    # docker build -t alpha-ai-frontend .
    # docker push your-registry/alpha-ai-frontend:latest
    
    # AWS S3 deployment
    # aws s3 sync .next/ s3://your-bucket --delete
    # aws cloudfront create-invalidation --distribution-id YOUR_DISTRIBUTION_ID --paths "/*"
    
    Write-Success "Deployment completed successfully"
}

# Cleanup
function Cleanup {
    Write-Step "Cleaning up temporary files..."
    
    try {
        # Remove temporary files
        if (Test-Path "*.gz") {
            Remove-Item "*.gz" -Force
        }
        
        Write-Success "Cleanup completed"
    }
    catch {
        Write-Warning "Cleanup failed: $_"
    }
}

# Main deployment flow
function Main {
    Write-Info "Starting Alpha AI Frontend Deployment..."
    Write-Info "Environment: $Environment"
    Write-Info "Build Path: $BuildPath"
    Write-Info "Output Path: $OutputPath"
    Write-Info ""
    
    $startTime = Get-Date
    
    try {
        # Change to build directory if specified
        if ($BuildPath -ne ".") {
            Set-Location $BuildPath
        }
        
        # Run deployment steps
        Test-DeploymentEnvironment
        Install-Dependencies
        Start-ApplicationTests
        Start-ApplicationBuild
        Optimize-Build
        New-DeploymentManifest
        
        $package = New-DeploymentPackage
        Publish-ToServer -PackagePath $package
        
        Cleanup
        
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        Write-Info ""
        Write-Success "🎉 Deployment completed successfully!"
        Write-Info "Total deployment time: $($duration.TotalMinutes.ToString('F2')) minutes"
        Write-Info "Deployment package: $package"
        
    }
    catch {
        Write-Error "Deployment failed: $_"
        exit 1
    }
}

# Run the main function
Main
