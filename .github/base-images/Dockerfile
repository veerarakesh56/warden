# NOT BUILT. Dependabot's reading copy of the base images, at their upstream (Docker Hub), at the digests in use.
#
# Dependabot's docker updater cannot read the real Dockerfiles' base images - their registry is the build argument
# BASE_IMAGE_REGISTRY, and a FROM line that starts with a variable is skipped - nor the CI service images, which
# live in workflow YAML. So they are named here, where it can: it proposes new digests (and patch tags) in this
# file. Such a proposal fails tests/test_base_image_mirror.py until the same reference is in mirror-images.yml, both
# Dockerfiles and ci-tool.yml; then run mirror-images.yml, which copies it into the mirror, before anything builds.
FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b
FROM postgres:16@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54
FROM mysql:8@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242
FROM redis:7@sha256:c6eabf748fc7a61dbb5a705c78bcf3d6377b1127a97d0ce965c11c44ba46896f
FROM mongo:7@sha256:9854f7139445d766a9523571d6f047530c45547460ffcf8259eb2bf4264632ca
FROM rancher/k3s:v1.35.5-k3s1@sha256:2074403abe1bded11ef3dde09d457e13be8e0b64c218b1c4f8269b4565cfbc65
