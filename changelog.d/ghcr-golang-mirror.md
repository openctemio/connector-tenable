### Changed: builder image from the ghcr mirror

- The builder image is pulled from `ghcr.io/openctemio/mirror` (same digest) instead of public.ecr.aws, whose rate limit (429) failed image builds.
