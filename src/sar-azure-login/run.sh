#!/bin/bash
./snowalert/src/sar-azure-login/readData.py | ./snowalert/src/sar-azure-login/stats.R | ./snowalert/src/sar-azure-login/writeBack.py

