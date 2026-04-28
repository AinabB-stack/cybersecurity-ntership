# ============================================================
# WEEK 6 - Docker Security Best Practices
# ============================================================

# Use specific version (never use 'latest' in production)
FROM node:20.11.0-alpine3.19

# Run as non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy package files first (better layer caching)
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY src/ ./src/

# Set correct permissions
RUN chown -R appuser:appgroup /app

# Create logs directory
RUN mkdir -p /app/logs && chown appuser:appgroup /app/logs

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

# Read-only filesystem (security hardening)
# Run: docker run --read-only --tmpfs /tmp ...

CMD ["node", "src/server.js"]
