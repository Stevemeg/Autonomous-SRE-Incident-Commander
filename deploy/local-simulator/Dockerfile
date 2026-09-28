# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
#
# LOCAL TEST INFRASTRUCTURE ONLY - never published, never deployed by a production overlay.
#
# The production backend image excludes the deterministic simulator package (FR-INT-04,
# .dockerignore), so its worker can only run the live profile, which refuses to start until a
# live model provider exists (GAP-08). For the kind acceptance run, this image adds exactly one
# thing on top of the *final* production image - src/asic/simulators - so the worker's
# simulator profile can run. Every other layer, and every other file, is the production image.
# scripts/deployment_smoke.py builds it from the supplied backend image and verifies the layer
# prefix. The build context is a temporary directory containing only the simulator package.
ARG BACKEND_IMAGE
FROM ${BACKEND_IMAGE}
LABEL org.opencontainers.image.title="ASIC backend + deterministic simulators (LOCAL TEST ONLY)" \
      org.opencontainers.image.description="Final backend image plus src/asic/simulators for the kind simulator profile"
COPY --chown=10001:10001 src/asic/simulators ./src/asic/simulators
