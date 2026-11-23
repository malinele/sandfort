# Sandfort API image. Build from the repository root:
#   docker build -f deploy/Dockerfile -t sandfort .

FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml ./
COPY src ./src
# The package version comes from git, which a checkout copy does not carry (the build then falls
# back to 0.1.0.dev0). Pass the version to stamp with --build-arg SANDFORT_VERSION=0.1.0b61;
# deploy/redeploy-beta.sh derives it from git describe. The CI image workflow
# (.github/workflows/release.yml) should pass the same argument, computed from the tag.
# Empty (the default) leaves version detection alone. The build backend is hatch-vcs, which
# honours only the unscoped SETUPTOOLS_SCM_PRETEND_VERSION, so the project wheel is built in
# its own step (the variable lives in that shell alone) and the dependencies in a second step,
# where a dependency built from an sdist keeps its own version.
ARG SANDFORT_VERSION=""
RUN if [ -n "${SANDFORT_VERSION}" ]; then \
      export SETUPTOOLS_SCM_PRETEND_VERSION="${SANDFORT_VERSION}"; \
    fi \
    && pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .
# asyncpg serves the app; psycopg serves alembic's synchronous migrations.
RUN pip wheel --no-cache-dir --wheel-dir /wheels /wheels/sandfort-*.whl uvicorn asyncpg \
      "psycopg[binary]"

FROM python:3.12-slim
# The commit this image was built from; CI and compose pass it with --build-arg.
ARG SANDFORT_BUILD_SHA=""
LABEL org.opencontainers.image.revision="${SANDFORT_BUILD_SHA}" \
      org.opencontainers.image.source="https://github.com/malinele/sandfort"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 sandfort
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/*.whl \
    && rm -rf /wheels
WORKDIR /app
# alembic.ini resolves script_location as src/sandfort/migrations next to itself.
COPY alembic.ini ./
COPY src/sandfort/migrations ./src/sandfort/migrations
RUN printf '%s\n' "${SANDFORT_BUILD_SHA}" > /app/BUILD_SHA
USER sandfort
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && exec sandfort-server --host 0.0.0.0 --port 8000"]
