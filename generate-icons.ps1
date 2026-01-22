# PowerShell script to generate favicon and logo variants from logo.png
# Requires .NET System.Drawing

Add-Type -AssemblyName System.Drawing

$sourcePath = "c:\Users\DarkNode\Desktop\Projet Web\Alpha AI\logo.png"
$outputDir = "c:\Users\DarkNode\Desktop\Projet Web\Alpha AI\frontend\public"

# Create output directory if it doesn't exist
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

Write-Host "Loading source image: $sourcePath" -ForegroundColor Cyan

# Load the source image
$sourceImage = [System.Drawing.Image]::FromFile($sourcePath)
Write-Host "Source image loaded: $($sourceImage.Width)x$($sourceImage.Height)" -ForegroundColor Green

# Function to resize image
function Resize-Image {
    param(
        [System.Drawing.Image]$Image,
        [int]$Width,
        [int]$Height
    )
    
    $destRect = New-Object System.Drawing.Rectangle(0, 0, $Width, $Height)
    $destImage = New-Object System.Drawing.Bitmap($Width, $Height)
    
    $destImage.SetResolution($Image.HorizontalResolution, $Image.VerticalResolution)
    
    $graphics = [System.Drawing.Graphics]::FromImage($destImage)
    $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
    $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    
    $wrapMode = New-Object System.Drawing.Imaging.ImageAttributes
    $wrapMode.SetWrapMode([System.Drawing.Drawing2D.WrapMode]::TileFlipXY)
    
    $graphics.DrawImage($Image, $destRect, 0, 0, $Image.Width, $Image.Height, [System.Drawing.GraphicsUnit]::Pixel, $wrapMode)
    
    $graphics.Dispose()
    
    return $destImage
}

# Favicon sizes (ICO format supports multiple sizes)
$faviconSizes = @(16, 32, 48)

Write-Host "`nGenerating favicon sizes..." -ForegroundColor Cyan

foreach ($size in $faviconSizes) {
    $resized = Resize-Image -Image $sourceImage -Width $size -Height $size
    $outputPath = Join-Path $outputDir "favicon-${size}x${size}.png"
    $resized.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $resized.Dispose()
    Write-Host "  Created: favicon-${size}x${size}.png" -ForegroundColor Green
}

# Standard favicon.ico (32x32)
$favicon32 = Resize-Image -Image $sourceImage -Width 32 -Height 32
$faviconPath = Join-Path $outputDir "favicon.ico"
$favicon32.Save($faviconPath, [System.Drawing.Imaging.ImageFormat]::Icon)
$favicon32.Dispose()
Write-Host "  Created: favicon.ico (32x32)" -ForegroundColor Green

# Logo sizes for web
$logoSizes = @(
    @{Width=64; Height=64; Name="logo-small"},
    @{Width=128; Height=128; Name="logo-medium"},
    @{Width=256; Height=256; Name="logo-large"},
    @{Width=512; Height=512; Name="logo-xlarge"}
)

Write-Host "`nGenerating logo sizes..." -ForegroundColor Cyan

foreach ($logoSize in $logoSizes) {
    $resized = Resize-Image -Image $sourceImage -Width $logoSize.Width -Height $logoSize.Height
    $outputPath = Join-Path $outputDir "$($logoSize.Name).png"
    $resized.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $resized.Dispose()
    Write-Host "  Created: $($logoSize.Name).png ($($logoSize.Width)x$($logoSize.Height))" -ForegroundColor Green
}

# Copy original as logo.png
$originalLogoPath = Join-Path $outputDir "logo.png"
Copy-Item -Path $sourcePath -Destination $originalLogoPath -Force
Write-Host "  Copied: logo.png (original)" -ForegroundColor Green

# Apple Touch Icon (180x180)
$appleTouchIcon = Resize-Image -Image $sourceImage -Width 180 -Height 180
$appleTouchPath = Join-Path $outputDir "apple-touch-icon.png"
$appleTouchIcon.Save($appleTouchPath, [System.Drawing.Imaging.ImageFormat]::Png)
$appleTouchIcon.Dispose()
Write-Host "  Created: apple-touch-icon.png (180x180)" -ForegroundColor Green

# Android Chrome icons
$androidSizes = @(192, 512)
Write-Host "`nGenerating Android Chrome icons..." -ForegroundColor Cyan

foreach ($size in $androidSizes) {
    $resized = Resize-Image -Image $sourceImage -Width $size -Height $size
    $outputPath = Join-Path $outputDir "android-chrome-${size}x${size}.png"
    $resized.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $resized.Dispose()
    Write-Host "  Created: android-chrome-${size}x${size}.png" -ForegroundColor Green
}

# Cleanup
$sourceImage.Dispose()

Write-Host "`n✅ All icons generated successfully!" -ForegroundColor Green
Write-Host "Output directory: $outputDir" -ForegroundColor Cyan

# List all generated files
Write-Host "`nGenerated files:" -ForegroundColor Yellow
Get-ChildItem -Path $outputDir -Filter "*.png" | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor White }
Get-ChildItem -Path $outputDir -Filter "*.ico" | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor White }
