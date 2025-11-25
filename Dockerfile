FROM node:18-alpine@sha256:8d6421d663b4c28fd3ebc498332f249011d118945588d0a35cb9bc4b8ca09d9e

ENV TERM=xterm-256color

# Install Python for the scanner
RUN apk add --no-cache python3

# Create app group and user with specific IDs
RUN addgroup -g 1001 appuser && \
    adduser -D -u 1001 -G appuser appuser

# Set working directory
WORKDIR /app

# Copy the scanner script, BOM files, and entrypoint
COPY --chown=appuser:appuser --chmod=0555 scan_compromised_packages.py .
COPY --chown=appuser:appuser --chmod=0555 bom-*.json ./
COPY --chown=appuser:appuser --chmod=0555 entrypoint.sh .

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Create a volume mount point for the project to scan with proper permissions
RUN mkdir -p /project && chown -R appuser:appuser /project
VOLUME ["/project"]

# Default to scanning /project directory
WORKDIR /project

# Switch to non-root user
USER appuser

# Set the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]

# Default argument is current directory
CMD ["."]
