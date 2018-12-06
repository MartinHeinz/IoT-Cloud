#!/bin/bash
set -e

POSTGRES="psql --username ${POSTGRES_USER}"

echo "Creating database: ${TESTING_DB_NAME}"

$POSTGRES <<EOSQL
CREATE DATABASE ${TESTING_DB_NAME} OWNER ${POSTGRES_USER};
EOSQL
