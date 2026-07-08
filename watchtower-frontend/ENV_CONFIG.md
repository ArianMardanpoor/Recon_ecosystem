# Environment Configuration Guide

## Local Development Setup

Create a `.env` file in the root directory with the following variables:

```bash
# API Configuration
VITE_API_URL=http://localhost:3131/api
VITE_API_TOKEN=your-api-token-here
```

## Environment Variables

### Required Variables

- **VITE_API_URL**: The base URL of your Watchtower API
  - Example: `http://localhost:3131/api`
  - Production: `https://api.watchtower.example.com/api`

- **VITE_API_TOKEN**: Your API authentication token
  - Obtain from your Watchtower API administrator
  - Default: `a21uc0lzeTcK` (for development)

### Optional Variables

- **VITE_ANALYTICS_ENDPOINT**: Analytics service endpoint (Umami, Plausible, etc.)
  - Example: `https://analytics.example.com`

- **VITE_ANALYTICS_WEBSITE_ID**: Website ID for analytics tracking
  - Example: `your-website-id`

## Setup Instructions

### 1. Create .env File

```bash
# Linux/Mac
touch .env

# Windows
echo. > .env
```

### 2. Add Configuration

Edit `.env` and add:

```
VITE_API_URL=http://localhost:3131/api
VITE_API_TOKEN=a21uc0lzeTcK
```

### 3. Restart Development Server

```bash
# Stop the current server (Ctrl+C)
# Then restart
pnpm dev
```

## Troubleshooting

### API Connection Issues

1. **Check API URL**: Ensure `VITE_API_URL` is correct
2. **Check API Token**: Verify `VITE_API_TOKEN` is valid
3. **Check Network**: Ensure API server is running and accessible
4. **Check Timeout**: API timeout is set to 30 seconds

### Environment Variables Not Loading

1. Restart the development server
2. Clear browser cache (Ctrl+Shift+Delete)
3. Check `.env` file is in the root directory
4. Verify no spaces around `=` in `.env`

### Analytics Not Working

1. Analytics is optional - the app works without it
2. If you want analytics, ensure:
   - `VITE_ANALYTICS_ENDPOINT` is a valid URL
   - `VITE_ANALYTICS_WEBSITE_ID` is correct
   - Analytics service is accessible

## Production Deployment

For production, set environment variables through:

1. **Environment Variables Panel** (Manus UI)
2. **Docker**: Pass as `-e` flags
3. **Docker Compose**: Add to `.env` file
4. **Server**: Set in system environment

Example for Docker:

```bash
docker run -e VITE_API_URL=https://api.example.com/api \
           -e VITE_API_TOKEN=your-token \
           watchtower-v2
```

## Security Notes

- Never commit `.env` file to Git
- Use `.gitignore` to exclude `.env`
- Rotate API tokens regularly
- Use HTTPS for production API URLs
- Don't share API tokens in logs or error messages
