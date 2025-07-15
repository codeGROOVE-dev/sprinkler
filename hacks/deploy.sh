#!/bin/sh
PROJECT="ready-to-review"
export KO_DOCKER_REPO="gcr.io/${PROJECT}/sprinkler"

gcloud run deploy sprinkler --image="$(ko publish ./cmd/server)" --region us-central1 --project "${PROJECT}"
