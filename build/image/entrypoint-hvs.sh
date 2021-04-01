#!/bin/bash

USER_ID=$(id -u)
LOG_PATH=/var/log/hvs
CONFIG_PATH=/etc/hvs
CERTS_DIR=${CONFIG_PATH}/certs
TRUSTED_CERTS=${CERTS_DIR}/trustedca
ROOT_CA_DIR=${TRUSTED_CERTS}/root
ENDORSEMENTS_CA_DIR=${CERTS_DIR}/endorsement
PRIVACY_CA_DIR=${TRUSTED_CERTS}/privacy-ca
TRUSTED_KEYS_DIR=${CONFIG_PATH}/trusted-keys
CERTDIR_TRUSTEDJWTCERTS=${CERTS_DIR}/trustedjwt

if [ ! -f $CONFIG_PATH/.setup_done ]; then
  for directory in $LOG_PATH $CONFIG_PATH $CERTS_DIR $TRUSTED_CERTS $ROOT_CA_DIR $ENDORSEMENTS_CA_DIR $PRIVACY_CA_DIR $TRUSTED_KEYS_DIR $CERTDIR_TRUSTEDJWTCERTS ; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chown -R $USER_ID:$USER_ID $directory
    chmod 700 $directory
  done
  mv /opt/hvs/EndorsementCA-external.pem $ENDORSEMENTS_CA_DIR/
  hvs setup all --force
  if [ $? -ne 0 ]; then
    exit 1
  fi
  touch $CONFIG_PATH/.setup_done
fi

if [ ! -z $SETUP_TASK ]; then
  IFS=',' read -ra ADDR <<< "$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    hvs setup $task --force
    if [ $? -ne 0 ]; then
      exit 1
    fi
  done
fi

hvs run
