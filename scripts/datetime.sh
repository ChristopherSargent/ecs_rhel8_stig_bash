#!/bin/bash
# Christopher Sargent 05312023
set -x #echo on

# Add date time stamp to root and jboss prompts/history's
echo "export PROMPT_COMMAND='echo -n \[\$(date +%F-%T)\]\ '" >> /etc/bashrc && echo "export HISTTIMEFORMAT='%F-%T '" >> /etc/bashrc && source /etc/bashrc

# Add ll alias 
echo "alias ll='ls -alF'" >> /etc/bashrc && source /etc/bashrc
