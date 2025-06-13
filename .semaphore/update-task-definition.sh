#!/bin/bash

set -e

# Updates a task definition with a new container image
# Returns the new task definition ARN
#
# Required environment variables:
# TASK_FAMILY - Task definition family
# CONTAINER_NAME - Container name to update
# IMAGE - New container image to deploy

if [ -z "$TASK_FAMILY" ] || [ -z "$CONTAINER_NAME" ] || [ -z "$IMAGE" ]; then
  echo "Error: TASK_FAMILY, CONTAINER_NAME, and IMAGE environment variables are required"
  exit 1
fi

TASK_DEFINITION="$(aws ecs describe-task-definition --task-definition=$TASK_FAMILY | jq '.taskDefinition')"

# Remove fields that can't be used in register-task-definition
TASK_DEFINITION="$(jq 'del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)' <<< "$TASK_DEFINITION")"

# Find the index of the specified container
CONTAINER_INDEX="$(jq --arg NAME "$CONTAINER_NAME" '.containerDefinitions | map(.name) | index($NAME)' <<< "$TASK_DEFINITION")"

if [ "$CONTAINER_INDEX" = "null" ]; then
  echo "Error: Container '$CONTAINER_NAME' not found in task definition"
  exit 1
fi

# Update the container image
NEW_TASK_DEFINITION="$(jq --arg INDEX "$CONTAINER_INDEX" --arg IMAGE "$IMAGE" '.containerDefinitions[$INDEX | tonumber].image = $IMAGE' <<< "$TASK_DEFINITION")"

# Register the new task definition
NEW_TASK_DEFINITION_ARN="$(aws ecs register-task-definition --cli-input-json "$NEW_TASK_DEFINITION" --output text --query 'taskDefinition.taskDefinitionArn')"

echo "$TASK_DEFINITION" > task-definition.json
echo "$NEW_TASK_DEFINITION" > new-task-definition.json

echo "Applying update:" >&2
diff -u task-definition.json new-task-definition.json >&2 || :

echo "$NEW_TASK_DEFINITION_ARN"
