#!/bin/bash

USER_ID=$(id -u)
COMPONENT_NAME=authservice
LOG_PATH=/var/log/$COMPONENT_NAME/
CONFIG_PATH=/etc/$COMPONENT_NAME/
CERTS_PATH=$CONFIG_PATH/certs
CERTDIR_TOKENSIGN=$CERTS_PATH/tokensign
CERTDIR_TRUSTEDJWTCAS=$CERTS_PATH/trustedca

if [ ! -f $CONFIG_PATH/.setup_done ]; then
  for directory in $LOG_PATH $CONFIG_PATH $CERTS_PATH $CERTDIR_TOKENSIGN $CERTDIR_TRUSTEDJWTCAS; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chown -R $USER_ID:$USER_ID $directory
    chmod 700 $directory
  done
  aas setup all --force
  if [ $? -ne 0 ]; then
    exit 1
  fi
  touch $CONFIG_PATH/.setup_done
fi

if [ ! -z $SETUP_TASK ]; then
  IFS=',' read -ra ADDR <<< "$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    aas setup $task --force
    if [ $? -ne 0 ]; then
      exit 1
    fi
  done
fi

aas run
