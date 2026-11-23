# Sandfort API image for the self-host bundle: installs the signed SERVER WHEEL, no source build.
# The bundle root is the build context (deploy/selfhost/compose.yml sets it), and the wheel sits
# in that root next to SHA256SUMS. Verify the bundle before you build (see INSTALL.md).
#   docker build -f deploy/selfhost/Dockerfile -t sandfort-api --network host .
#
# Differences from deploy/Dockerfile in the repository: the wheel comes from the bundle (no
# git, no hatch-vcs), and alembic.ini plus the migration files are not copied: the migrations
# ship inside the wheel and `python -m sandfort.admin_cli migrate` applies them from there.

FROM python:3.12-slim
# The commit this release was built from (RELEASE.txt names it); compose passes it.
ARG SANDFORT_BUILD_SHA=""
LABEL org.opencontainers.image.revision="${SANDFORT_BUILD_SHA}" \
      org.opencontainers.image.source="https://github.com/malinele/sandfort"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 sandfort
# The server wheel is sandfort-<version>-*.whl. The pattern needs a digit after the hyphen, so
# it never matches the SDK or CLI wheels (sandfort_sdk-*, sandfort_cli-*).
COPY sandfort-[0-9]*.whl /wheels/
# asyncpg serves the app; psycopg serves alembic's synchronous migrations.
RUN pip install --no-cache-dir /wheels/sandfort-[0-9]*.whl uvicorn asyncpg "psycopg[binary]" \
    && rm -rf /wheels
WORKDIR /app
RUN printf '%s\n' "${SANDFORT_BUILD_SHA}" > /app/BUILD_SHA
USER sandfort
EXPOSE 8000
CMD ["sh", "-c", "python -m sandfort.admin_cli migrate && exec sandfort-server --host 0.0.0.0 --port 8000"]
