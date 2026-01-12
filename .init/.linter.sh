#!/bin/bash
cd /home/kavia/workspace/code-generation/secure-access-portal-304372-304381/backend_api
npm run lint
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

