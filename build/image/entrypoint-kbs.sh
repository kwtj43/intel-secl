#!/bin/bash

USER_ID=$(id -u)
COMPONENT_NAME=kbs
PRODUCT_HOME=/opt/$COMPONENT_NAME
LOG_PATH=/var/log/$COMPONENT_NAME
CONFIG_PATH=/etc/$COMPONENT_NAME
CERTS_PATH=$CONFIG_PATH/certs
CERTDIR_TRUSTEDJWTCERTS=$CERTS_PATH/trustedjwt
CERTDIR_TRUSTEDCAS=$CERTS_PATH/trustedca
KEYS_PATH=$PRODUCT_HOME/keys
KEYS_TRANSFER_POLICY_PATH=$PRODUCT_HOME/keys-transfer-policy
SAML_CERTS_PATH=$CERTS_PATH/saml
TPM_IDENTITY_CERTS_PATH=$CERTS_PATH/tpm-identity

if [ ! -f $CONFIG_PATH/.setup_done ]; then
  for directory in $PRODUCT_HOME $LOG_PATH $CONFIG_PATH $CERTS_PATH $CERTDIR_TRUSTEDJWTCERTS $CERTDIR_TRUSTEDCAS $KEYS_PATH $KEYS_TRANSFER_POLICY_PATH $SAML_CERTS_PATH $TPM_IDENTITY_CERTS_PATH; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chown -R $USER_ID:$USER_ID $directory
    chmod 700 $directory
  done
  kbs setup all --force
  if [ $? -ne 0 ]; then
    exit 1
  fi
  touch $CONFIG_PATH/.setup_done
fi

if [ ! -z $SETUP_TASK ]; then
  IFS=',' read -ra ADDR <<< "$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    kbs setup $task --force
    if [ $? -ne 0 ]; then
      exit 1
    fi
  done
fi

kbs run
