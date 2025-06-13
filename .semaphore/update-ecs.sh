#!/bin/bash

set -e

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Updates an ECS service with a new container image.

Required options:
  -c, --cluster CLUSTER        ECS cluster name
  -t, --task-family FAMILY    Task definition family
  -i, --image IMAGE           New container image to deploy
  -s, --service SERVICE       ECS service name

Optional:
  -n, --container-name NAME   Container name to update (default: web)
  -h, --help                  Show this help message
EOF
  exit 1
}

# Initialize default values
CONTAINER_NAME="web"

# Parse command line options
while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--cluster)
      CLUSTER="$2"
      shift 2
      ;;
    -t|--task-family)
      TASK_FAMILY="$2"
      shift 2
      ;;
    -i|--image)
      IMAGE="$2"
      shift 2
      ;;
    -s|--service)
      SERVICE="$2"
      shift 2
      ;;
    -n|--container-name)
      CONTAINER_NAME="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Error: Unknown option $1"
      usage
      ;;
  esac
done

# Validate required parameters
if [ -z "$CLUSTER" ] || [ -z "$TASK_FAMILY" ] || [ -z "$IMAGE" ] || [ -z "$SERVICE" ]; then
  echo "Error: Missing required options"
  usage
fi

# Use the common script to update the task definition
export TASK_FAMILY CONTAINER_NAME IMAGE
NEW_TASK_DEFINITION_ARN="$(. "$(dirname "$0")/update-task-definition.sh")"

# Deploy the new task definition
aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" --task-definition "$NEW_TASK_DEFINITION_ARN" --deployment-configuration "deploymentCircuitBreaker={enable=true,rollback=true},maximumPercent=200,minimumHealthyPercent=100" --force-new-deployment >/dev/null

echo "Waiting for service to stabilize at the new revision..."

# Wait for the service to stabilize for up to 20 minutes
for i in {1..80}; do
  if aws ecs describe-services --cluster "$CLUSTER" --service "$SERVICE" --output json | jq -e \
    '.services | map(select((.deployments | length) != 1 or .runningCount != .desiredCount)) | length == 0' >/dev/null; then
    break
  fi
  sleep 15
done

if [ $i -eq 80 ]; then
  echo "Service failed to stabilize after 20 minutes"
  exit 1
fi
