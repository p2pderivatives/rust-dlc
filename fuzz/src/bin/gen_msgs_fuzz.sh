#!/bin/sh

MSGS=(OfferDlc AcceptDlc SignDlc)

for msg in ${MSGS[@]}; do
    cat ./msg_template.txt | sed s/MSG_NAME/$msg/g > $(echo $msg | tr '[:upper:]' '[:lower:]')_fuzz.rs
done
