#!/bin/bash
echo "**********************************"
echo "* Status of alertflex local node *"
echo "**********************************"
echo
altprobe status
echo
/var/ossec/bin/ossec-control status
echo
