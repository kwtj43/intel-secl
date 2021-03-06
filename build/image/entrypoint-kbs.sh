#!/bin/bash

COMPONENT_NAME=kbs
PRODUCT_HOME=/opt/$COMPONENT_NAME
BIN_PATH=$PRODUCT_HOME/bin
LIB_PATH=$PRODUCT_HOME/lib
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
  for directory in $PRODUCT_HOME $LOG_PATH $CONFIG_PATH $BIN_PATH $LIB_PATH $CERTS_PATH $CERTDIR_TRUSTEDJWTCERTS $CERTDIR_TRUSTEDCAS $KEYS_PATH $KEYS_TRANSFER_POLICY_PATH $SAML_CERTS_PATH $TPM_IDENTITY_CERTS_PATH; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chown -R $COMPONENT_NAME:$COMPONENT_NAME $directory
    chmod 700 $directory
  done
  mv /tmp/libkmip.so.0.2 $LIB_PATH/
  chown $COMPONENT_NAME:$COMPONENT_NAME $LIB_PATH/*
  chmod 700 $LIB_PATH/*
  ln -sfT $LIB_PATH/libkmip.so.0.2 $LIB_PATH/libkmip.so
  ln -sfT $LIB_PATH/libkmip.so.0.2 $LIB_PATH/libkmip.so.0
  export LD_LIBRARY_PATH=$LIB_PATH
  kbs setup all
  if [ $? -ne 0 ]; then
    exit 1
  fi
  touch $CONFIG_PATH/.setup_done
fi

kbs run